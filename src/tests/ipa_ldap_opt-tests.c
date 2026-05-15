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
#include "providers/be_dyndns.h"
#include "tests/common_check.h"

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

/* Mock parsing search base without overlinking the test */
errno_t sdap_parse_search_base(TALLOC_CTX *mem_ctx,
                               struct ldb_context *ldb,
                               struct dp_option *opts, int class,
                               struct sdap_search_base ***_search_bases)
{
    return EOK;
}

START_TEST(test_domain_to_basedn)
{
    int ret;
    int i;
    TALLOC_CTX *tmp_ctx;
    char *basedn;

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    ret = domain_to_basedn(tmp_ctx, NULL, &basedn);
    ck_assert_msg(ret == EINVAL,
                "domain_to_basedn does not fail with EINVAL if domain is NULL");

    ret = domain_to_basedn(tmp_ctx, "abc", NULL);
    ck_assert_msg(ret == EINVAL,
                "domain_to_basedn does not fail with EINVAL if basedn is NULL");

    for(i=0; test_domains[i].domain != NULL; i++) {
        ret = domain_to_basedn(tmp_ctx, test_domains[i].domain, &basedn);
        ck_assert_msg(ret == EOK, "domain_to_basedn failed");
        ck_assert_msg(strcmp(basedn, test_domains[i].basedn) == 0,
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
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(default_krb5_opts, KRB5_OPTS,
                             ipa_def_krb5_opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(ipa_dyndns_opts, DP_OPT_DYNDNS,
                             ad_dyndns_opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_dp_options(ipa_dyndns_opts, DP_OPT_DYNDNS,
                             default_dyndns_opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

START_TEST(test_compare_sdap_attrs)
{
    errno_t ret;

    /* General Attributes */
    ret = compare_sdap_attr_maps(generic_attr_map, SDAP_AT_GENERAL,
                                 ipa_attr_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* User Attributes */
    ret = compare_sdap_attr_maps(rfc2307_user_map, SDAP_OPTS_USER,
                                 ipa_user_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Group Attributes */
    ret = compare_sdap_attr_maps(rfc2307_group_map, SDAP_OPTS_GROUP,
                                 ipa_group_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Service Attributes */
    ret = compare_sdap_attr_maps(service_map, SDAP_OPTS_SERVICES,
                                 ipa_service_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* AutoFS Attributes */
    ret = compare_sdap_attr_maps(rfc2307_autofs_mobject_map,
                                 SDAP_OPTS_AUTOFS_MAP,
                                 ipa_autofs_mobject_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_sdap_attr_maps(rfc2307_autofs_entry_map,
                                 SDAP_OPTS_AUTOFS_ENTRY,
                                 ipa_autofs_entry_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

START_TEST(test_compare_2307_with_2307bis)
{
    errno_t ret;

    /* User Attributes */
    ret = compare_sdap_attr_maps(rfc2307_user_map, SDAP_OPTS_USER,
                                 rfc2307bis_user_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Group Attributes */
    ret = compare_sdap_attr_maps(rfc2307_group_map, SDAP_OPTS_GROUP,
                                 rfc2307bis_group_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* AutoFS Attributes */
    ret = compare_sdap_attr_maps(rfc2307_autofs_mobject_map,
                                 SDAP_OPTS_AUTOFS_MAP,
                                 rfc2307bis_autofs_mobject_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = compare_sdap_attr_maps(rfc2307_autofs_entry_map,
                                 SDAP_OPTS_AUTOFS_ENTRY,
                                 rfc2307bis_autofs_entry_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
}
END_TEST

static void fail_unless_dp_opt_is_terminator(struct dp_option *o)
{
    ck_assert_msg(o->opt_name == NULL,
                "Unexpected non-NULL for opt_name in dp_option");
    ck_assert_msg(o->type == 0,
                "Unexpected non-zero for type in dp_option");
    ck_assert_msg(o->def_val.string == NULL,
                "Unexpected non-NULL for def_val.string in dp_option");
    ck_assert_msg(o->val.string == NULL,
                "Unexpected non-NULL for val.string in dp_option");
}

static void fail_unless_sdap_opt_is_terminator(struct sdap_attr_map *m)
{
    ck_assert_msg(m->name == NULL,
                "Unexpected non-NULL for name in sdap_attr_map");
    ck_assert_msg(m->def_name == NULL,
                "Unexpected non-NULL for def_name in sdap_attr_map");
    ck_assert_msg(m->sys_name == NULL,
                "Unexpected non-NULL for sys_name in sdap_attr_map");
    ck_assert_msg(m->opt_name == NULL,
                "Unexpected non-NULL for opt_name in sdap_attr_map");
}

START_TEST(test_dp_opt_sentinel)
{
    fail_unless_dp_opt_is_terminator(&default_basic_opts[SDAP_OPTS_BASIC]);

    fail_unless_dp_opt_is_terminator(&default_krb5_opts[KRB5_OPTS]);

    fail_unless_dp_opt_is_terminator(&default_dyndns_opts[DP_OPT_DYNDNS]);

    fail_unless_dp_opt_is_terminator(&ad_basic_opts[AD_OPTS_BASIC]);
    fail_unless_dp_opt_is_terminator(&ad_def_ldap_opts[SDAP_OPTS_BASIC]);
    fail_unless_dp_opt_is_terminator(&ad_def_krb5_opts[KRB5_OPTS]);

    fail_unless_dp_opt_is_terminator(&ipa_basic_opts[IPA_OPTS_BASIC]);
    fail_unless_dp_opt_is_terminator(&ipa_def_ldap_opts[SDAP_OPTS_BASIC]);
    fail_unless_dp_opt_is_terminator(&ipa_def_krb5_opts[KRB5_OPTS]);

    fail_unless_dp_opt_is_terminator(&ad_dyndns_opts[DP_OPT_DYNDNS]);
    fail_unless_dp_opt_is_terminator(&ipa_dyndns_opts[DP_OPT_DYNDNS]);
}
END_TEST

START_TEST(test_sdap_opt_sentinel)
{
    fail_unless_sdap_opt_is_terminator(&generic_attr_map[SDAP_AT_GENERAL]);
    fail_unless_sdap_opt_is_terminator(&gen_ipa_attr_map[SDAP_AT_GENERAL]);
    fail_unless_sdap_opt_is_terminator(&gen_ad_attr_map[SDAP_AT_GENERAL]);
    fail_unless_sdap_opt_is_terminator(&ad_2008r2_attr_map[SDAP_AT_GENERAL]);
    fail_unless_sdap_opt_is_terminator(&ipa_attr_map[SDAP_AT_GENERAL]);

    fail_unless_sdap_opt_is_terminator(&rfc2307_user_map[SDAP_OPTS_USER]);
    fail_unless_sdap_opt_is_terminator(&rfc2307bis_user_map[SDAP_OPTS_USER]);
    fail_unless_sdap_opt_is_terminator(&gen_ad2008r2_user_map[SDAP_OPTS_USER]);
    fail_unless_sdap_opt_is_terminator(&ad_2008r2_user_map[SDAP_OPTS_USER]);
    fail_unless_sdap_opt_is_terminator(&ipa_user_map[SDAP_OPTS_USER]);

    fail_unless_sdap_opt_is_terminator(&rfc2307_group_map[SDAP_OPTS_GROUP]);
    fail_unless_sdap_opt_is_terminator(&rfc2307bis_group_map[SDAP_OPTS_GROUP]);
    fail_unless_sdap_opt_is_terminator(&gen_ad2008r2_group_map[SDAP_OPTS_GROUP]);
    fail_unless_sdap_opt_is_terminator(&ad_2008r2_group_map[SDAP_OPTS_GROUP]);
    fail_unless_sdap_opt_is_terminator(&ipa_group_map[SDAP_OPTS_GROUP]);

    fail_unless_sdap_opt_is_terminator(&native_sudorule_map[SDAP_OPTS_SUDO]);

    fail_unless_sdap_opt_is_terminator(&netgroup_map[SDAP_OPTS_NETGROUP]);
    fail_unless_sdap_opt_is_terminator(&ad_netgroup_map[SDAP_OPTS_NETGROUP]);
    fail_unless_sdap_opt_is_terminator(&ipa_netgroup_map[IPA_OPTS_NETGROUP]);

    fail_unless_sdap_opt_is_terminator(&ipa_host_map[SDAP_OPTS_HOST]);
    fail_unless_sdap_opt_is_terminator(&ipa_hostgroup_map[IPA_OPTS_HOSTGROUP]);
    fail_unless_sdap_opt_is_terminator(&ipa_selinux_user_map[IPA_OPTS_SELINUX_USERMAP]);
    fail_unless_sdap_opt_is_terminator(&ipa_view_map[IPA_OPTS_VIEW]);
    fail_unless_sdap_opt_is_terminator(&ipa_override_map[IPA_OPTS_OVERRIDE]);

    fail_unless_sdap_opt_is_terminator(&service_map[SDAP_OPTS_SERVICES]);
    fail_unless_sdap_opt_is_terminator(&ad_service_map[SDAP_OPTS_SERVICES]);
    fail_unless_sdap_opt_is_terminator(&ipa_service_map[SDAP_OPTS_SERVICES]);

    fail_unless_sdap_opt_is_terminator(&rfc2307_autofs_mobject_map[SDAP_OPTS_AUTOFS_MAP]);
    fail_unless_sdap_opt_is_terminator(&rfc2307bis_autofs_mobject_map[SDAP_OPTS_AUTOFS_MAP]);
    fail_unless_sdap_opt_is_terminator(&ad_autofs_mobject_map[SDAP_OPTS_AUTOFS_MAP]);
    fail_unless_sdap_opt_is_terminator(&ipa_autofs_mobject_map[SDAP_OPTS_AUTOFS_MAP]);

    fail_unless_sdap_opt_is_terminator(&rfc2307_autofs_entry_map[SDAP_OPTS_AUTOFS_ENTRY]);
    fail_unless_sdap_opt_is_terminator(&rfc2307bis_autofs_entry_map[SDAP_OPTS_AUTOFS_ENTRY]);
    fail_unless_sdap_opt_is_terminator(&ad_autofs_entry_map[SDAP_OPTS_AUTOFS_ENTRY]);
    fail_unless_sdap_opt_is_terminator(&ipa_autofs_entry_map[SDAP_OPTS_AUTOFS_ENTRY]);
}
END_TEST

START_TEST(test_copy_opts)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    struct dp_option *opts;

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    ret = dp_copy_defaults(tmp_ctx, ad_def_ldap_opts, SDAP_OPTS_BASIC, &opts);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    for (int i=0; i < SDAP_OPTS_BASIC; i++) {
        char *s1, *s2;
        bool b1, b2;
        int i1, i2;
        struct dp_opt_blob  bl1, bl2;

        switch (opts[i].type) {
        case DP_OPT_STRING:
            s1 = dp_opt_get_string(opts, i);
            s2 = opts[i].def_val.string;

            if (s1 != NULL || s2 != NULL) {
                ck_assert_msg(strcmp(s1, s2) == 0,
                            "Option %s does not have default value after copy\n",
                            opts[i].opt_name);
            }
            break;

        case DP_OPT_NUMBER:
            i1 = dp_opt_get_int(opts, i);
            i2 = opts[i].def_val.number;

            ck_assert_msg(i1 == i2,
                        "Option %s does not have default value after copy\n",
                        opts[i].opt_name);
            break;

        case DP_OPT_BOOL:
            b1 = dp_opt_get_bool(opts, i);
            b2 = opts[i].def_val.boolean;

            ck_assert_msg(b1 == b2,
                        "Option %s does not have default value after copy\n",
                        opts[i].opt_name);
            break;

        case DP_OPT_BLOB:
            bl1 = dp_opt_get_blob(opts, i);
            bl2 = opts[i].def_val.blob;

            ck_assert_msg(bl1.length == bl2.length,
                        "Blobs differ in size for option %s\n",
                        opts[i].opt_name);
            ck_assert_msg(memcmp(bl1.data, bl2.data, bl1.length) == 0,
                        "Blobs differ in value for option %s\n",
                        opts[i].opt_name);
        }
    }

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_copy_sdap_map)
{
    errno_t ret;
    struct sdap_attr_map *out_map;

    ret = sdap_copy_map(global_talloc_context,
                        rfc2307_user_map, SDAP_OPTS_USER, &out_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].def_name == NULL,
                "Unexpected NULL for def_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].sys_name == NULL,
                "Unexpected NULL for sys_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].opt_name == NULL,
                "Unexpected NULL for opt_name with idx: %d", SDAP_OPTS_USER);
    talloc_free(out_map);

    ret = sdap_copy_map(global_talloc_context,
                        rfc2307bis_user_map, SDAP_OPTS_USER, &out_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].def_name == NULL,
                "Unexpected NULL for def_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].sys_name == NULL,
                "Unexpected NULL for sys_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].opt_name == NULL,
                "Unexpected NULL for opt_name with idx: %d", SDAP_OPTS_USER);
    talloc_free(out_map);

    ret = sdap_copy_map(global_talloc_context,
                        ipa_user_map, SDAP_OPTS_USER, &out_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].def_name == NULL,
                "Unexpected NULL for def_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].sys_name == NULL,
                "Unexpected NULL for sys_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].opt_name == NULL,
                "Unexpected NULL for opt_name with idx: %d", SDAP_OPTS_USER);
    talloc_free(out_map);

    ret = sdap_copy_map(global_talloc_context,
                        gen_ad2008r2_user_map, SDAP_OPTS_USER, &out_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].def_name == NULL,
                "Unexpected NULL for def_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].sys_name == NULL,
                "Unexpected NULL for sys_name with idx: %d", SDAP_OPTS_USER);
    ck_assert_msg(out_map[SDAP_OPTS_USER].opt_name == NULL,
                "Unexpected NULL for opt_name with idx: %d", SDAP_OPTS_USER);
    talloc_free(out_map);
}
END_TEST

START_TEST(test_extra_opts)
{
    errno_t ret;
    char *extra_attrs[] =  { discard_const("foo"),
                             discard_const("baz:bar"),
                             NULL };
    struct sdap_attr_map *in_map;
    struct sdap_attr_map *out_map;
    size_t new_size;

    ret = sdap_copy_map(global_talloc_context, rfc2307_user_map,
                        SDAP_OPTS_USER, &in_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = sdap_extend_map(global_talloc_context,
                          in_map,
                          SDAP_OPTS_USER,
                          extra_attrs,
                          &out_map, &new_size);
    ck_assert_msg(ret == EOK, "[%s]", sss_strerror(ret));

    /* Two extra and sentinel */
    sss_ck_fail_if_msg(new_size == SDAP_OPTS_USER + 3,
            "new_size [%zu] mest not be equal to[%d]",
            new_size, SDAP_OPTS_USER + 3);
    /* Foo would be saved to sysdb verbatim */
    ck_assert_str_eq(out_map[SDAP_OPTS_USER].name, "foo");
    ck_assert_str_eq(out_map[SDAP_OPTS_USER].sys_name, "foo");
    /* Bar would be saved to sysdb as baz */
    ck_assert_str_eq(out_map[SDAP_OPTS_USER+1].name, "bar");
    ck_assert_str_eq(out_map[SDAP_OPTS_USER+1].sys_name, "baz");
    ck_assert_msg(out_map[SDAP_OPTS_USER+2].name == NULL,
                "Unexpected NULL for name with id: %d", SDAP_OPTS_USER + 2);

    talloc_free(out_map);
}
END_TEST

START_TEST(test_no_extra_opts)
{
    errno_t ret;
    struct sdap_attr_map *in_map;
    struct sdap_attr_map *out_map;
    size_t new_size;

    ret = sdap_copy_map(global_talloc_context, rfc2307_user_map,
                        SDAP_OPTS_USER, &in_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = sdap_extend_map(global_talloc_context,
                          in_map,
                          SDAP_OPTS_USER,
                          NULL,
                          &out_map, &new_size);
    ck_assert_msg(ret == EOK, "[%s]", sss_strerror(ret));
    /* Attributes and sentinel */
    sss_ck_fail_if_msg(new_size == SDAP_OPTS_USER + 1,
            "new_size [%zu] mest not be equal to[%d]",
            new_size, SDAP_OPTS_USER + 1);
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with id: %d", SDAP_OPTS_USER);

    talloc_free(out_map);
}
END_TEST

START_TEST(test_extra_opts_neg)
{
    errno_t ret;
    char *extra_attrs[] =  { discard_const(":foo"),
                             discard_const("bar:"),
                             NULL };
    struct sdap_attr_map *in_map;
    struct sdap_attr_map *out_map;
    size_t new_size;

    ret = sdap_copy_map(global_talloc_context, rfc2307_user_map,
                        SDAP_OPTS_USER, &in_map);
    ck_assert_msg(ret == EOK, "[%s]", sss_strerror(ret));

    ret = sdap_extend_map(global_talloc_context,
                          in_map,
                          SDAP_OPTS_USER,
                          extra_attrs,
                          &out_map, &new_size);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));
    /* The faulty attributes would be just skipped */
    sss_ck_fail_if_msg(new_size == SDAP_OPTS_USER + 1,
            "new_size [%zu] mest not be equal to[%d]",
            new_size, SDAP_OPTS_USER + 1);
    ck_assert_msg(out_map[SDAP_OPTS_USER].name == NULL,
                "Unexpected NULL for name with id: %d", SDAP_OPTS_USER);

    talloc_free(out_map);
}
END_TEST

START_TEST(test_extra_opts_dup)
{
    errno_t ret;
    char *extra_attrs[] =  { discard_const("name:foo"),
                             NULL };
    struct sdap_attr_map *in_map;
    struct sdap_attr_map *out_map;
    size_t new_size;

    ret = sdap_copy_map(global_talloc_context, rfc2307_user_map,
                        SDAP_OPTS_USER, &in_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    ret = sdap_extend_map(global_talloc_context,
                          in_map,
                          SDAP_OPTS_USER,
                          extra_attrs,
                          &out_map, &new_size);
    ck_assert_msg(ret == ERR_DUP_EXTRA_ATTR, "[%s]", sss_strerror(ret));

    talloc_free(out_map);
}
END_TEST

START_TEST(test_extra_opts_empty_name)
{
    errno_t ret;
    char *extra_attrs[] =  { discard_const(SYSDB_UUID":bar"),
                             NULL };
    struct sdap_attr_map *in_map;
    struct sdap_attr_map *out_map;
    size_t new_size;

    ret = sdap_copy_map(global_talloc_context, rfc2307_user_map,
                        SDAP_OPTS_USER, &in_map);
    ck_assert_msg(ret == EOK, "[%s]", strerror(ret));

    /* Make sure the name if really NULL */
    ck_assert_msg(rfc2307_user_map[SDAP_AT_USER_UUID].name == NULL,
                "The reference name is not NULL anymore, "
                "please choose a different attribute.");

    ret = sdap_extend_map(global_talloc_context,
                          in_map,
                          SDAP_OPTS_USER,
                          extra_attrs,
                          &out_map, &new_size);
    ck_assert_msg(ret == ERR_DUP_EXTRA_ATTR, "[%s]", sss_strerror(ret));

    talloc_free(out_map);
}
END_TEST

Suite *ipa_ldap_opt_suite (void)
{
    Suite *s = suite_create ("ipa_ldap_opt");

    TCase *tc_ipa_ldap_opt = tcase_create ("ipa_ldap_opt");

    tcase_add_test (tc_ipa_ldap_opt, test_compare_opts);
    tcase_add_test (tc_ipa_ldap_opt, test_compare_sdap_attrs);
    tcase_add_test (tc_ipa_ldap_opt, test_compare_2307_with_2307bis);
    tcase_add_test (tc_ipa_ldap_opt, test_dp_opt_sentinel);
    tcase_add_test (tc_ipa_ldap_opt, test_sdap_opt_sentinel);
    suite_add_tcase (s, tc_ipa_ldap_opt);

    TCase *tc_ipa_utils = tcase_create ("ipa_utils");
    tcase_add_test (tc_ipa_utils, test_domain_to_basedn);
    suite_add_tcase (s, tc_ipa_utils);

    TCase *tc_dp_opts = tcase_create ("dp_opts");
    tcase_add_test (tc_dp_opts, test_copy_opts);
    suite_add_tcase (s, tc_dp_opts);

    TCase *tc_sdap_opts = tcase_create ("sdap_opts");
    tcase_add_test (tc_sdap_opts, test_copy_sdap_map);
    suite_add_tcase (s, tc_sdap_opts);

    TCase *tc_extra_opts = tcase_create ("extra_opts");
    tcase_add_test (tc_extra_opts, test_extra_opts);
    tcase_add_test (tc_extra_opts, test_no_extra_opts);
    tcase_add_test (tc_extra_opts, test_extra_opts_neg);
    tcase_add_test (tc_extra_opts, test_extra_opts_dup);
    tcase_add_test (tc_extra_opts, test_extra_opts_empty_name);
    suite_add_tcase (s, tc_extra_opts);

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
