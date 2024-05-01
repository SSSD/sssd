/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: AD access control filter tests

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <unistd.h>
#include <sys/types.h>
#include <ifaddrs.h>
#include <arpa/inet.h>

#include "providers/ad/ad_pac.h"
#include "util/crypto/sss_crypto.h"
#include "util/util_sss_idmap.h"

/* In order to access opaque types */
#include "providers/ad/ad_common.c"

#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_krb5.h"

#define DOMNAME     "domname"
#define SUBDOMNAME  "sub."DOMNAME
#define REALMNAME   DOMNAME
#define HOST_NAME   "ad."REALMNAME

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_AUTHID       "host/"HOST_NAME
#define KEYTAB_TEST_PRINC TEST_AUTHID"@"REALMNAME
#define KEYTAB_PATH       TESTS_PATH"/keytab_test.keytab"

#define ONEWAY_DOMNAME     "ONEWAY"
#define ONEWAY_HOST_NAME   "ad."ONEWAY_DOMNAME

#define ONEWAY_KEYTAB_PATH       TESTS_PATH"/oneway_test.keytab"
#define ONEWAY_AUTHID            "host/"ONEWAY_HOST_NAME
#define ONEWAY_TEST_PRINC        ONEWAY_AUTHID"@"ONEWAY_DOMNAME

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_ad_sysdb.ldb"
#define TEST_ID_PROVIDER "ad"
#define TEST_DOM1_NAME "test_sysdb_subdomains_1"
#define TEST_DOM2_NAME "child2.test_sysdb_subdomains_2"
#define TEST_USER "test_user"

static bool call_real_sasl_options;

const char *domains[] = { TEST_DOM1_NAME,
                          TEST_DOM2_NAME,
                          NULL };
struct ad_sysdb_test_ctx {
    struct sss_test_ctx *tctx;
};

static int test_ad_sysdb_setup(void **state)
{
    struct ad_sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context,
                           struct ad_sysdb_test_ctx);
    assert_non_null(test_ctx);

    test_dom_suite_setup(TESTS_PATH);

    test_ctx->tctx = create_multidom_test_ctx(test_ctx, TESTS_PATH,
                                              TEST_CONF_DB, domains,
                                              TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    *state = test_ctx;
    return 0;
}

static int test_ad_sysdb_teardown(void **state)
{
    struct ad_sysdb_test_ctx *test_ctx =
        talloc_get_type(*state, struct ad_sysdb_test_ctx);

    test_multidom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, domains);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_check_if_pac_is_available(void **state)
{
    int ret;
    struct ad_sysdb_test_ctx *test_ctx =
        talloc_get_type(*state, struct ad_sysdb_test_ctx);
    struct dp_id_data *ar;
    struct ldb_message *msg = NULL;
    struct sysdb_attrs *attrs;

    ret = check_if_pac_is_available(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ar = talloc_zero(test_ctx, struct dp_id_data);
    assert_non_null(ar);

    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, EINVAL);

    ar->filter_type = BE_FILTER_NAME;
    ar->filter_value = discard_const(TEST_USER);

    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_add_user(test_ctx->tctx->dom, TEST_USER, 123, 456, NULL, NULL,
                         NULL, NULL, NULL, 0, 0);
    assert_int_equal(ret, EOK);

    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, ENOENT);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_PAC_BLOB, "pac");
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(test_ctx->tctx->dom, TEST_USER, attrs,
                              SYSDB_MOD_REP);

    /* PAC available but too old */
    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, ENOENT);

    talloc_free(attrs);
    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_PAC_BLOB_EXPIRE, 123);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(test_ctx->tctx->dom, TEST_USER, attrs,
                              SYSDB_MOD_REP);

    /* PAC available but still too old */
    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, ENOENT);

    talloc_free(attrs);
    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_time_t(attrs, SYSDB_PAC_BLOB_EXPIRE, time(NULL) + 10);
    assert_int_equal(ret, EOK);

    ret = sysdb_set_user_attr(test_ctx->tctx->dom, TEST_USER, attrs,
                              SYSDB_MOD_REP);

    /* PAC available but still too old */
    ret = check_if_pac_is_available(test_ctx, test_ctx->tctx->dom, ar, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_string_equal(ldb_msg_find_attr_as_string(msg, SYSDB_NAME, "x"),
                        TEST_USER);

    talloc_free(attrs);
    talloc_free(ar);
}

#define TEST_PAC_BASE64 \
    "BQAAAAAAAAABAAAA6AEAAFgAAAAAAAAACgAAABAAAABAAgAAAA" \
    "AAAAwAAAA4AAAAUAIAAAAAAAAGAAAAFAAAAIgCAAAAAAAABwAA" \
    "ABQAAACgAgAAAAAAAAEQCADMzMzM2AEAAAAAAAAAAAIA2hr35p" \
    "Ji0QH/////////f/////////9/4veKrwAP0AHit/TZyQ/QAf//" \
    "//////9/BgAGAAQAAgAGAAYACAACAAAAAAAMAAIAAAAAABAAAg" \
    "AAAAAAFAACAAAAAAAYAAIATwAAAFAEAAABAgAABQAAABwAAgAg" \
    "AAAAAAAAAAAAAAAAAAAAAAAAABIAFAAgAAIABAAGACQAAgAoAA" \
    "IAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "AAAAAAEAAAAsAAIAAAAAAAAAAAAAAAAAAwAAAAAAAAADAAAAdA" \
    "B1ADEAAAADAAAAAAAAAAMAAAB0ACAAdQAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "UAAAD9ogAABwAAAAECAAAHAAAAXAQAAAcAAABWBAAABwAAAImm" \
    "AAAHAAAACgAAAAAAAAAJAAAAQQBEAC0AUwBFAFIAVgBFAFIAAA" \
    "ADAAAAAAAAAAIAAABBAEQABAAAAAEEAAAAAAAFFQAAAPgSE9xH" \
    "8xx2Ry8u1wEAAAAwAAIABwAAAAUAAAABBQAAAAAABRUAAAApyU" \
    "/ZwjzDeDZVh/hUBAAAgD5SqNxk0QEGAHQAdQAxABgAEAAQACgA" \
    "AAAAAAAAAAB0AHUAMQBAAGEAZAAuAGQAZQB2AGUAbABBAEQALg" \
    "BEAEUAVgBFAEwAdv///4yBQZ5ZQnp3qwj2lKGcd0UAAAAAdv//" \
    "/39fn4UneD5l6YxP8w/U0coAAAAA"

#define TEST_PAC_RESOURCE_GROUPS_BASE64 \
    "BQAAAAAAAAABAAAA8AEAAFgAAAAAAAAACgAAABQAAABIAgAA" \
    "AAAAAAwAAABYAAAAYAIAAAAAAAAGAAAAEAAAALgCAAAAAAAA" \
    "BwAAABQAAADIAgAAAAAAAAEQCADMzMzM4AEAAAAAAAAAAAIA" \
    "Rr0gPUQO1AH/////////f/////////9/TRPNRwtu0wFN0zZy" \
    "1G7TAf////////9/CgAKAAQAAgAKAAoACAACAAAAAAAMAAIA" \
    "AAAAABAAAgAAAAAAFAACAAAAAAAYAAIACwAAAFEEAAABAgAA" \
    "AwAAABwAAgAgAgAAAAAAAAAAAAAAAAAAAAAAAAQABgAgAAIA" \
    "BgAIACQAAgAoAAIAAAAAAAAAAAAQAgAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAEAAAAsAAIANAACAAEAAAA4AAIA" \
    "BQAAAAAAAAAFAAAAdAB1AHMAZQByAAAABQAAAAAAAAAFAAAA" \
    "dAB1AHMAZQByAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAwAAAAECAAAHAAAA" \
    "YgQAAAcAAABjBAAABwAAAAMAAAAAAAAAAgAAAEQAQwAEAAAA" \
    "AAAAAAMAAABXAEkATgAAAAQAAAABBAAAAAAABRUAAAAkYm0r" \
    "SyFumd73jX0BAAAAMAACAAcAAAABAAAAAQEAAAAAABIBAAAA" \
    "BAAAAAEEAAAAAAAFFQAAACRibStLIW6Z3veNfQEAAABoBAAA" \
    "BwAAIAAAAACAEuVfRA7UAQoAdAB1AHMAZQByAAAAAAAoABAA" \
    "HAA4AAAAAAAAAAAAdAB1AHMAZQByAEAAdwBpAG4ALgB0AHIA" \
    "dQBzAHQALgB0AGUAcwB0AFcASQBOAC4AVABSAFUAUwBUAC4A" \
    "VABFAFMAVAAAAAAAEAAAAOGTj7I9Qn7XebOqdHb///+fHhrZ" \
    "kBt0So4jOFBk84sDAAAAAA=="

#define TEST_PAC_WITH_HAS_SAM_NAME_AND_SID_BASE64 \
    "BgAAAAAAAAABAAAA2AEAAGgAAAAAAAAACgAAABgAAABAAgAA" \
    "AAAAAAwAAACIAAAAWAIAAAAAAAAGAAAAEAAAAOACAAAAAAAA" \
    "BwAAABAAAADwAgAAAAAAABAAAAAQAAAAAAMAAAAAAAABEAgA" \
    "zMzMzMgBAAAAAAAAAAACAHQG3etmONgB/////////3//////" \
    "////f1IR75ZZV9cBUtFYwSJY1wH/////////fw4ADgAEAAIA" \
    "DgAOAAgAAgAAAAAADAACAAAAAAAQAAIAAAAAABQAAgAAAAAA" \
    "GAACACwAAQDoAwAAAQIAAAEAAAAcAAIAIAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAWABgAIAACAA4AEAAkAAIAKAACAAAAAAAAAAAA" \
    "EAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAA" \
    "LAACAAAAAAAAAAAAAAAAAAcAAAAAAAAABwAAAHYAYQBnAHIA" \
    "YQBuAHQAAAAHAAAAAAAAAAcAAABWAGEAZwByAGEAbgB0AAAA" \
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" \
    "AAAAAAAAAAAAAAAAAQAAAAECAAAHAAAADAAAAAAAAAALAAAA" \
    "TwBUAEgARQBSAC0AQQBEAC0ARABDAAAACAAAAAAAAAAHAAAA" \
    "TwBUAEgARQBSAEEARAAAAAQAAAABBAAAAAAABRUAAADjfjpn" \
    "NKqt8DV6HtgBAAAAMAACAAcAAAABAAAAAQEAAAAAABIBAAAA" \
    "gOAL92Y42AEOAHYAYQBnAHIAYQBuAHQAJgAYABYAQAADAAAA" \
    "DgBYABwAaAAAAAAAdgBhAGcAcgBhAG4AdABAAG8AdABoAGUA" \
    "cgAtAGEAZAAuAHYAbQAAAE8AVABIAEUAUgAtAEEARAAuAFYA" \
    "TQAAAHYAYQBnAHIAYQBuAHQAAAABBQAAAAAABRUAAADjfjpn" \
    "NKqt8DV6HtjoAwAAAAAAABAAAACHjVhlIcvUmxiq0L8QAAAA" \
    "yYHF7QwPjMVsbvTCEAAAAEr+xJAskwH6q5I2uw=="

static void test_ad_get_data_from_pac(void **state)
{
    int ret;
    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;
    uint8_t *test_pac_blob;
    size_t test_pac_blob_size;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);

    test_pac_blob = sss_base64_decode(test_ctx, TEST_PAC_BASE64,
                                      &test_pac_blob_size);
    assert_non_null(test_pac_blob_size);

    ret = ad_get_data_from_pac(test_ctx, 0, test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);
    assert_non_null(logon_info);
    assert_string_equal(logon_info->info3.base.account_name.string, "tu1");
    assert_string_equal(logon_info->info3.base.full_name.string, "t u");
    assert_int_equal(logon_info->info3.base.rid, 1104);
    assert_int_equal(logon_info->info3.base.primary_gid, 513);
    assert_int_equal(logon_info->info3.base.groups.count, 5);
    assert_string_equal(logon_info->info3.base.logon_domain.string, "AD");
    assert_int_equal(logon_info->info3.sidcount, 1);

    assert_non_null(upn_dns_info);
    assert_string_equal(upn_dns_info->upn_name, "tu1@ad.devel");
    assert_string_equal(upn_dns_info->dns_domain_name, "AD.DEVEL");
    assert_int_equal(upn_dns_info->flags, 0);

    talloc_free(logon_info);
    talloc_free(upn_dns_info);

    ret = ad_get_data_from_pac(test_ctx, CHECK_PAC_UPN_DNS_INFO_PRESENT,
                               test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);
    talloc_free(logon_info);
    talloc_free(upn_dns_info);

    ret = ad_get_data_from_pac(test_ctx, CHECK_PAC_CHECK_UPN_DNS_INFO_EX,
                               test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);
    talloc_free(logon_info);
    talloc_free(upn_dns_info);

    ret = ad_get_data_from_pac(test_ctx, CHECK_PAC_UPN_DNS_INFO_EX_PRESENT,
                               test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, ERR_CHECK_PAC_FAILED);
    assert_null(logon_info);
    assert_null(upn_dns_info);

    talloc_free(test_pac_blob);
}

static void test_ad_get_sids_from_pac(void **state)
{
    int ret;
    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;
    uint8_t *test_pac_blob;
    size_t test_pac_blob_size;
    char *user_sid;
    char *primary_group_sid;
    size_t num_sids;
    char **sid_list;
    struct sss_idmap_ctx *idmap_ctx;
    enum idmap_error_code err;
    size_t c;
    size_t s;

    const char *sid_check_list[] = { "S-1-5-21-3692237560-1981608775-3610128199-513",
                                     "S-1-5-21-3692237560-1981608775-3610128199-1110",
                                     "S-1-5-21-3692237560-1981608775-3610128199-1116",
                                     "S-1-5-21-3692237560-1981608775-3610128199-41725",
                                     "S-1-5-21-3692237560-1981608775-3610128199-42633",
                                     "S-1-5-21-3645884713-2026060994-4169618742-1108",
                                     NULL };

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);

    err = sss_idmap_init(sss_idmap_talloc, test_ctx, sss_idmap_talloc_free,
                         &idmap_ctx);
    assert_int_equal(err, IDMAP_SUCCESS);

    test_pac_blob = sss_base64_decode(test_ctx, TEST_PAC_BASE64,
                                      &test_pac_blob_size);
    assert_non_null(test_pac_blob_size);

    ret = ad_get_data_from_pac(test_ctx, 0, test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);

    ret = ad_get_sids_from_pac(test_ctx, idmap_ctx, logon_info, &user_sid,
                               &primary_group_sid, &num_sids, &sid_list);
    assert_int_equal(ret, EOK);
    assert_string_equal(user_sid,
                        "S-1-5-21-3692237560-1981608775-3610128199-1104");
    assert_string_equal(primary_group_sid,
                        "S-1-5-21-3692237560-1981608775-3610128199-513");
    assert_int_equal(num_sids, 6);

    for (c = 0; sid_check_list[c] != NULL; c++) {
        for (s = 0; s < num_sids; s++) {
            if (strcmp(sid_check_list[c], sid_list[s]) == 0) {
                break;
            }
        }
        if (s == num_sids) {
            fail_msg("SID [%s] not found in SID list.", sid_check_list[c]);
        }
    }

    assert_non_null(upn_dns_info);
    assert_string_equal(upn_dns_info->upn_name, "tu1@ad.devel");
    assert_string_equal(upn_dns_info->dns_domain_name, "AD.DEVEL");
    assert_int_equal(upn_dns_info->flags, 0);

    talloc_free(test_pac_blob);
    talloc_free(logon_info);
    talloc_free(upn_dns_info);
    talloc_free(user_sid);
    talloc_free(primary_group_sid);
    talloc_free(sid_list);
    sss_idmap_free(idmap_ctx);
}

#ifdef HAVE_STRUCT_PAC_LOGON_INFO_RESOURCE_GROUPS
static void test_ad_get_sids_from_pac_with_resource_groups(void **state)
{
    int ret;
    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;
    uint8_t *test_pac_blob;
    size_t test_pac_blob_size;
    char *user_sid;
    char *primary_group_sid;
    size_t num_sids;
    char **sid_list;
    struct sss_idmap_ctx *idmap_ctx;
    enum idmap_error_code err;
    size_t c;
    size_t s;

    const char *sid_check_list[] = { "S-1-5-21-728588836-2574131531-2106456030-513",
                                     "S-1-5-21-728588836-2574131531-2106456030-1122",
                                     "S-1-5-21-728588836-2574131531-2106456030-1123",
                                     "S-1-5-21-728588836-2574131531-2106456030-1128",
                                     "S-1-18-1",
                                     NULL };

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);

    err = sss_idmap_init(sss_idmap_talloc, test_ctx, sss_idmap_talloc_free,
                         &idmap_ctx);
    assert_int_equal(err, IDMAP_SUCCESS);

    test_pac_blob = sss_base64_decode(test_ctx, TEST_PAC_RESOURCE_GROUPS_BASE64,
                                      &test_pac_blob_size);
    assert_non_null(test_pac_blob_size);

    ret = ad_get_data_from_pac(test_ctx, 0, test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);

    ret = ad_get_sids_from_pac(test_ctx, idmap_ctx, logon_info, &user_sid,
                               &primary_group_sid, &num_sids, &sid_list);
    assert_int_equal(ret, EOK);
    assert_string_equal(user_sid,
                        "S-1-5-21-728588836-2574131531-2106456030-1105");
    assert_string_equal(primary_group_sid,
                        "S-1-5-21-728588836-2574131531-2106456030-513");
    assert_int_equal(num_sids, 5);

    for (c = 0; sid_check_list[c] != NULL; c++) {
        for (s = 0; s < num_sids; s++) {
            if (strcmp(sid_check_list[c], sid_list[s]) == 0) {
                break;
            }
        }
        if (s == num_sids) {
            fail_msg("SID [%s] not found in SID list.", sid_check_list[c]);
        }
    }

    assert_non_null(upn_dns_info);
    assert_string_equal(upn_dns_info->upn_name, "tuser@win.trust.test");
    assert_string_equal(upn_dns_info->dns_domain_name, "WIN.TRUST.TEST");
    assert_int_equal(upn_dns_info->flags, 0);

    talloc_free(test_pac_blob);
    talloc_free(logon_info);
    talloc_free(upn_dns_info);
    talloc_free(user_sid);
    talloc_free(primary_group_sid);
    talloc_free(sid_list);
    sss_idmap_free(idmap_ctx);
}
#endif

#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
static void test_ad_pac_with_has_sam_name_and_sid(void **state)
{
    int ret;
    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;
    uint8_t *test_pac_blob;
    size_t test_pac_blob_size;
    char *sid_str = NULL;
    struct sss_idmap_ctx *idmap_ctx;
    enum idmap_error_code err;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);

    err = sss_idmap_init(sss_idmap_talloc, test_ctx, sss_idmap_talloc_free,
                         &idmap_ctx);

    assert_int_equal(err, IDMAP_SUCCESS);

    test_pac_blob = sss_base64_decode(test_ctx, TEST_PAC_WITH_HAS_SAM_NAME_AND_SID_BASE64,
                                      &test_pac_blob_size);
    assert_non_null(test_pac_blob_size);

    ret = ad_get_data_from_pac(test_ctx,
                               CHECK_PAC_UPN_DNS_INFO_PRESENT
                                    |CHECK_PAC_CHECK_UPN_DNS_INFO_EX
                                    |CHECK_PAC_UPN_DNS_INFO_EX_PRESENT,
                               test_pac_blob, test_pac_blob_size,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);
    assert_non_null(logon_info);
    assert_string_equal(logon_info->info3.base.account_name.string, "vagrant");
    assert_string_equal(logon_info->info3.base.full_name.string, "Vagrant");
    assert_int_equal(logon_info->info3.base.rid, 1000);
    assert_int_equal(logon_info->info3.base.primary_gid, 513);
    assert_int_equal(logon_info->info3.base.groups.count, 1);
    assert_string_equal(logon_info->info3.base.logon_domain.string, "OTHERAD");
    assert_int_equal(logon_info->info3.sidcount, 1);

    assert_non_null(upn_dns_info);
    assert_string_equal(upn_dns_info->upn_name, "vagrant@other-ad.vm");
    assert_string_equal(upn_dns_info->dns_domain_name, "OTHER-AD.VM");
    assert_int_equal(upn_dns_info->flags, 3);
    assert_string_equal(upn_dns_info->ex.sam_name_and_sid.samaccountname, "vagrant");

    sss_idmap_smb_sid_to_sid(idmap_ctx, upn_dns_info->ex.sam_name_and_sid.objectsid, &sid_str);
    assert_string_equal(sid_str, "S-1-5-21-1731886819-4037913140-3625876021-1000");

    talloc_free(test_pac_blob);
    talloc_free(logon_info);
    talloc_free(upn_dns_info);
    talloc_free(sid_str);
    sss_idmap_free(idmap_ctx);
}

static void test_ad_pac_missing_upn_dns_info(void **state)
{
    int ret;
    DATA_BLOB blob;
    DATA_BLOB new_blob;
    uint8_t *test_pac_blob;
    size_t test_pac_blob_size;
    struct PAC_BUFFER *pac_buffers;
    struct PAC_DATA *pac_data;
    struct ndr_pull *ndr_pull;
    struct PAC_DATA *orig_pac_data;
    enum ndr_err_code ndr_err;
    size_t c;
    TALLOC_CTX *tmp_ctx;
    struct PAC_LOGON_INFO *logon_info;
    struct PAC_UPN_DNS_INFO *upn_dns_info;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    test_pac_blob = sss_base64_decode(tmp_ctx, TEST_PAC_WITH_HAS_SAM_NAME_AND_SID_BASE64,
                                      &test_pac_blob_size);
    assert_non_null(test_pac_blob_size);

    blob.data = test_pac_blob;
    blob.length = test_pac_blob_size;

    ndr_pull = ndr_pull_init_blob(&blob, tmp_ctx);
    assert_non_null(ndr_pull);
    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC; /* FIXME: is this really needed ? */

    orig_pac_data = talloc_zero(tmp_ctx, struct PAC_DATA);
    assert_non_null(orig_pac_data);

    ndr_err = ndr_pull_PAC_DATA(ndr_pull, NDR_SCALARS|NDR_BUFFERS, orig_pac_data);
    assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

    pac_buffers = talloc_array(tmp_ctx, struct PAC_BUFFER, 1);
    assert_non_null(pac_buffers);

    pac_data = talloc_zero(tmp_ctx, struct PAC_DATA);
    assert_non_null(pac_data);

    for(c = 0; c < orig_pac_data->num_buffers; c++) {
        if (orig_pac_data->buffers[c].type == PAC_TYPE_LOGON_INFO) {
            pac_buffers[0] = orig_pac_data->buffers[c];
            break;
        }
    }

    pac_data->num_buffers = 1;
    pac_data->version = 0;
    pac_data->buffers = pac_buffers;

    ndr_err = ndr_push_struct_blob(&new_blob, tmp_ctx, pac_data,
                                   (ndr_push_flags_fn_t)ndr_push_PAC_DATA);
    assert_true(NDR_ERR_CODE_IS_SUCCESS(ndr_err));

    ret = ad_get_data_from_pac(test_ctx, 0,
                               new_blob.data, new_blob.length,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, EOK);
    assert_non_null(logon_info);
    assert_null(upn_dns_info);
    talloc_free(logon_info);

    ret = ad_get_data_from_pac(test_ctx, CHECK_PAC_UPN_DNS_INFO_PRESENT,
                               new_blob.data, new_blob.length,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, ERR_CHECK_PAC_FAILED);
    assert_null(logon_info);
    assert_null(upn_dns_info);

    ret = ad_get_data_from_pac(test_ctx, CHECK_PAC_UPN_DNS_INFO_EX_PRESENT,
                               new_blob.data, new_blob.length,
                               &logon_info, &upn_dns_info);
    assert_int_equal(ret, ERR_CHECK_PAC_FAILED);
    assert_null(logon_info);
    assert_null(upn_dns_info);


    talloc_free(pac_buffers);
    talloc_free(pac_data);
    talloc_free(orig_pac_data);
    talloc_free(test_pac_blob);
    talloc_free(ndr_pull);
    talloc_free(tmp_ctx);
}

#endif

static void test_ad_get_pac_data_from_user_entry(void **state)
{
    int ret;
    struct ldb_message *user_msg;
    struct ldb_val val;
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    struct sss_idmap_ctx *idmap_ctx;
    enum idmap_error_code err;
    char *username;
    char *user_sid;
    char *primary_group_sid;
    size_t num_sids;
    char **sid_list;
    size_t c;
    size_t s;
    const char *sid_check_list[] = { "S-1-5-21-3692237560-1981608775-3610128199-513",
                                     "S-1-5-21-3692237560-1981608775-3610128199-1110",
                                     "S-1-5-21-3692237560-1981608775-3610128199-1116",
                                     "S-1-5-21-3692237560-1981608775-3610128199-41725",
                                     "S-1-5-21-3692237560-1981608775-3610128199-42633",
                                     "S-1-5-21-3645884713-2026060994-4169618742-1108",
                                     NULL };

    err = sss_idmap_init(sss_idmap_talloc, test_ctx, sss_idmap_talloc_free,
                         &idmap_ctx);
    assert_int_equal(err, IDMAP_SUCCESS);

    user_msg = ldb_msg_new(test_ctx);
    assert_non_null(user_msg);

    ret = ldb_msg_add_string(user_msg, SYSDB_NAME, "username");
    assert_int_equal(ret, EOK);
    ret = ldb_msg_add_string(user_msg, SYSDB_OBJECTCATEGORY, SYSDB_USER_CLASS);
    assert_int_equal(ret, EOK);
    ret = ldb_msg_add_string(user_msg, SYSDB_PAC_BLOB_EXPIRE, "12345");
    assert_int_equal(ret, EOK);
    val.data = sss_base64_decode(test_ctx, TEST_PAC_BASE64, &val.length);
    ret = ldb_msg_add_value(user_msg, SYSDB_PAC_BLOB, &val, NULL);
    assert_int_equal(ret, EOK);


    ret = ad_get_pac_data_from_user_entry(test_ctx, user_msg, idmap_ctx,
                                          &username, &user_sid,
                                          &primary_group_sid, &num_sids,
                                          &sid_list);
    assert_int_equal(ret, EOK);
    assert_string_equal(username, "username");
    assert_string_equal(user_sid,
                        "S-1-5-21-3692237560-1981608775-3610128199-1104");
    assert_string_equal(primary_group_sid,
                        "S-1-5-21-3692237560-1981608775-3610128199-513");
    assert_int_equal(num_sids, 6);
    for (c = 0; sid_check_list[c] != NULL; c++) {
        for (s = 0; s < num_sids; s++) {
            if (strcmp(sid_check_list[c], sid_list[s]) == 0) {
                break;
            }
        }
        if (s == num_sids) {
            fail_msg("SID [%s] not found in SID list.", sid_check_list[c]);
        }
    }

    talloc_free(username);
    talloc_free(user_sid);
    talloc_free(primary_group_sid);
    talloc_free(sid_list);
    talloc_free(val.data);
    talloc_free(user_msg);
    sss_idmap_free(idmap_ctx);
}

krb5_error_code __wrap_krb5_kt_default(krb5_context context, krb5_keytab *id)
{
    return krb5_kt_resolve(context, KEYTAB_PATH, id);
}

struct ad_common_test_ctx {
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;

    struct sss_domain_info *dom;
    struct sss_domain_info *subdom;
};

static int test_ad_common_setup(void **state)
{
    struct ad_common_test_ctx *test_ctx;

    test_dom_suite_setup(TESTS_PATH);

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->dom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->dom);
    test_ctx->dom->name = discard_const(DOMNAME);

    test_ctx->subdom = talloc_zero(test_ctx, struct sss_domain_info);
    assert_non_null(test_ctx->subdom);
    test_ctx->subdom->name = discard_const(SUBDOMNAME);
    test_ctx->subdom->parent = test_ctx->dom;

    test_ctx->ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(test_ctx->ad_ctx);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_ad_common_teardown(void **state)
{
    int ret;
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());

    ret = rmdir(TESTS_PATH);
    assert_return_code(ret, errno);

    return 0;
}

static void test_ad_create_1way_trust_options(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    const char *s;

    call_real_sasl_options = true;
    /* Make sure this is not the keytab that __wrap_krb5_kt_default uses */
    mock_keytab_with_contents(test_ctx, ONEWAY_KEYTAB_PATH, ONEWAY_TEST_PRINC);

    test_ctx->subdom->name = discard_const(ONEWAY_DOMNAME);
    test_ctx->ad_ctx->ad_options = ad_create_trust_options(test_ctx->ad_ctx,
                                                          NULL,
                                                          NULL,
                                                          NULL,
                                                          test_ctx->subdom,
                                                          NULL,
                                                          ONEWAY_HOST_NAME,
                                                          ONEWAY_KEYTAB_PATH,
                                                          ONEWAY_AUTHID);
    assert_non_null(test_ctx->ad_ctx->ad_options);

    assert_int_equal(test_ctx->ad_ctx->ad_options->id->schema_type,
                     SDAP_SCHEMA_AD);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_DOMAIN);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_HOSTNAME);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_HOST_NAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KEYTAB);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_KEYTAB_PATH);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_KEYTAB);
    assert_non_null(s);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_AUTHID);
    assert_non_null(s);
    assert_string_equal(s, ONEWAY_AUTHID);

    talloc_free(test_ctx->ad_ctx->ad_options);

    unlink(ONEWAY_KEYTAB_PATH);
}
static void test_ad_create_2way_trust_options(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    const char *s;

    call_real_sasl_options = true;
    mock_keytab_with_contents(test_ctx, KEYTAB_PATH, KEYTAB_TEST_PRINC);
    test_ctx->subdom->name = discard_const(DOMNAME);

    test_ctx->ad_ctx->ad_options = ad_create_trust_options(
                                        test_ctx->ad_ctx,
                                        NULL,
                                        NULL,
                                        NULL,
                                        test_ctx->subdom,
                                        REALMNAME,
                                        HOST_NAME,
                                        NULL,
                                        NULL);

    assert_non_null(test_ctx->ad_ctx->ad_options);

    assert_int_equal(test_ctx->ad_ctx->ad_options->id->schema_type,
                     SDAP_SCHEMA_AD);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_DOMAIN);
    assert_non_null(s);
    assert_string_equal(s, DOMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->basic,
                          AD_HOSTNAME);
    assert_non_null(s);
    assert_string_equal(s, HOST_NAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_KEYTAB);
    assert_null(s); /* This is the system keytab */

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_KRB5_REALM);
    assert_non_null(s);
    assert_string_equal(s, REALMNAME);

    s = dp_opt_get_string(test_ctx->ad_ctx->ad_options->id->basic,
                          SDAP_SASL_AUTHID);
    assert_non_null(s);
    assert_string_equal(s, TEST_AUTHID);

    talloc_free(test_ctx->ad_ctx->ad_options);

    unlink(KEYTAB_PATH);
}

static int
test_ldap_conn_setup(void **state)
{
    struct ad_common_test_ctx *test_ctx;
    errno_t ret;
    struct sdap_domain *sdom;
    struct ad_id_ctx *ad_ctx;
    struct ad_id_ctx *subdom_ad_ctx;
    struct sdap_id_conn_ctx *subdom_ldap_ctx;

    ret = test_ad_common_setup((void **) &test_ctx);
    assert_int_equal(ret, EOK);

    mock_keytab_with_contents(test_ctx, KEYTAB_PATH, KEYTAB_TEST_PRINC);

    ad_ctx = test_ctx->ad_ctx;

    test_ctx->ad_ctx->ad_options = ad_create_trust_options(
                                        ad_ctx,
                                        NULL,
                                        NULL,
                                        NULL,
                                        test_ctx->subdom,
                                        REALMNAME,
                                        HOST_NAME,
                                        NULL,
                                        NULL);

    assert_non_null(ad_ctx->ad_options);

    ad_ctx->gc_ctx = talloc_zero(ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(ad_ctx->gc_ctx);

    ad_ctx->ldap_ctx = talloc_zero(ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(ad_ctx->ldap_ctx);

    ad_ctx->sdap_id_ctx = talloc_zero(ad_ctx, struct sdap_id_ctx);
    assert_non_null(ad_ctx->sdap_id_ctx);

    ad_ctx->sdap_id_ctx->opts = talloc_zero(ad_ctx->sdap_id_ctx,
                                            struct sdap_options);
    assert_non_null(ad_ctx->sdap_id_ctx->opts);

    ret = sdap_domain_add(ad_ctx->sdap_id_ctx->opts, test_ctx->dom, &sdom);
    assert_int_equal(ret, EOK);
    sdom->pvt = ad_ctx;

    subdom_ad_ctx = talloc_zero(test_ctx, struct ad_id_ctx);
    assert_non_null(subdom_ad_ctx);

    subdom_ldap_ctx = talloc_zero(subdom_ad_ctx, struct sdap_id_conn_ctx);
    assert_non_null(subdom_ldap_ctx);
    subdom_ad_ctx->ldap_ctx = subdom_ldap_ctx;

    ret = sdap_domain_add(ad_ctx->sdap_id_ctx->opts, test_ctx->subdom, &sdom);
    assert_int_equal(ret, EOK);
    sdom->pvt = subdom_ad_ctx;

    test_ctx->subdom_ad_ctx = subdom_ad_ctx;

    *state = test_ctx;
    return 0;
}

static int
test_ldap_conn_teardown(void **state)
{
    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                  struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    unlink(KEYTAB_PATH);

    talloc_free(test_ctx->subdom_ad_ctx);
    talloc_free(test_ctx->ad_ctx->ad_options);
    talloc_free(test_ctx->ad_ctx->gc_ctx);
    talloc_free(test_ctx->ad_ctx->ldap_ctx);
    talloc_free(test_ctx->ad_ctx->sdap_id_ctx);

    test_ad_common_teardown((void **) &test_ctx);
    return 0;
}

errno_t __wrap_sdap_select_principal_from_keytab_sync(TALLOC_CTX *mem_ctx,
                                               const char *princ_str,
                                               const char *realm_str,
                                               const char *keytab_name,
                                               char **sasl_primary,
                                               char **sasl_realm)
{
    if (strcasestr(princ_str, "host/") != NULL) {
        *sasl_primary = talloc_strdup(mem_ctx, princ_str);
    } else {
        *sasl_primary = talloc_asprintf(mem_ctx, "host/%s", princ_str);
    }
    *sasl_realm = talloc_strdup(mem_ctx, realm_str);
    return 0;
}

errno_t
__real_sdap_set_sasl_options(struct sdap_options *id_opts,
                             char *default_primary,
                             char *default_realm,
                             const char *keytab_path);
errno_t
__wrap_sdap_set_sasl_options(struct sdap_options *id_opts,
                             char *default_primary,
                             char *default_realm,
                             const char *keytab_path)
{
    /* Pretend SASL is fine */
    if (call_real_sasl_options == true) {
        return __real_sdap_set_sasl_options(id_opts,
                                            default_primary,
                                            default_realm,
                                            keytab_path);
    }

    return EOK;
}

void test_ad_get_dom_ldap_conn(void **state)
{
    struct sdap_id_conn_ctx *conn;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn = ad_get_dom_ldap_conn(test_ctx->ad_ctx, test_ctx->dom);
    assert_true(conn == test_ctx->ad_ctx->ldap_ctx);

    conn = ad_get_dom_ldap_conn(test_ctx->ad_ctx, test_ctx->subdom);
    assert_true(conn == test_ctx->subdom_ad_ctx->ldap_ctx);
}

void test_gc_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    assert_true(dp_opt_get_bool(test_ctx->ad_ctx->ad_options->basic,
                                AD_ENABLE_GC));
    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    /* If there is a fallback, we should ignore the offline mode */
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[1]->ignore_mark_offline);
    assert_null(conn_list[2]);
    talloc_free(conn_list);

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->subdom_ad_ctx->ldap_ctx);
    /* Subdomain error should not set the backend offline! */
    assert_true(conn_list[1]->ignore_mark_offline);
    talloc_free(conn_list);

    dp_opt_set_bool(test_ctx->ad_ctx->ad_options->basic, AD_ENABLE_GC, false);
    assert_false(dp_opt_get_bool(test_ctx->ad_ctx->ad_options->basic,
                                 AD_ENABLE_GC));

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_gc_conn_list(test_ctx, test_ctx->ad_ctx, test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->subdom_ad_ctx->ldap_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);
}

void test_ldap_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn_list = ad_ldap_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_ldap_conn_list(test_ctx,
                                  test_ctx->ad_ctx,
                                  test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->subdom_ad_ctx->ldap_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);
}

void test_user_conn_list(void **state)
{
    struct sdap_id_conn_ctx **conn_list;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    conn_list = ad_user_conn_list(test_ctx, test_ctx->ad_ctx,
                                  test_ctx->dom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->ldap_ctx);
    assert_false(conn_list[0]->ignore_mark_offline);
    assert_null(conn_list[1]);
    talloc_free(conn_list);

    conn_list = ad_user_conn_list(test_ctx, test_ctx->ad_ctx,
                                  test_ctx->subdom);
    assert_non_null(conn_list);

    assert_true(conn_list[0] == test_ctx->ad_ctx->gc_ctx);
    assert_true(conn_list[0]->ignore_mark_offline);
    assert_true(conn_list[1] == test_ctx->subdom_ad_ctx->ldap_ctx);
    /* Subdomain error should not set the backend offline! */
    assert_true(conn_list[1]->ignore_mark_offline);
    talloc_free(conn_list);
}

void test_netlogon_get_domain_info(void **state)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct ldb_val val = { 0 };
    char *flat_name;
    char *site;
    char *forest;

    struct ad_common_test_ctx *test_ctx = talloc_get_type(*state,
                                                     struct ad_common_test_ctx);
    assert_non_null(test_ctx);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = netlogon_get_domain_info(test_ctx, attrs, false, NULL, NULL, NULL);
    assert_int_equal(ret, ENOENT);

    ret = sysdb_attrs_add_val(attrs, AD_AT_NETLOGON, &val);
    assert_int_equal(ret, EOK);

    ret = netlogon_get_domain_info(test_ctx, attrs, false, NULL, NULL, NULL);
    assert_int_equal(ret, EBADMSG);

    talloc_free(attrs);
    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    val.data = sss_base64_decode(test_ctx, "FwAAAP0zAABsGcIYI7j2TL97Rd+TvpATAmFkBWRldmVsAMAYCWFkLXNlcnZlcsAYAkFEAAlBRC1TRVJWRVIAABdEZWZhdWx0LUZpcnN0LVNpdGUtTmFtZQDAQAUAAAD/////", &val.length);
    assert_non_null(val.data);

    ret = sysdb_attrs_add_val(attrs, AD_AT_NETLOGON, &val);
    assert_int_equal(ret, EOK);

    ret = netlogon_get_domain_info(test_ctx, attrs, false, &flat_name, &site, &forest);
    assert_int_equal(ret, EOK);
    assert_string_equal(flat_name, "AD");
    assert_string_equal(site, "Default-First-Site-Name");
    assert_string_equal(forest, "ad.devel");

    /* missing site */
    talloc_free(flat_name);
    talloc_free(site);
    talloc_free(forest);
    talloc_free(val.data);
    talloc_free(attrs);
    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    val.data = sss_base64_decode(test_ctx, "FwAAAH0zAABsGcIYI7j2TL97Rd+TvpATAmFkBWRldmVsAMAYCWFkLXNlcnZlcsAYAkFEAAlBRC1TRVJWRVIAABdEZWZhdWx0LUZpcnN0LVNpdGUtTmFtZQAABQAAAP////8=", &val.length);
    assert_non_null(val.data);

    ret = sysdb_attrs_add_val(attrs, AD_AT_NETLOGON, &val);
    assert_int_equal(ret, EOK);

    ret = netlogon_get_domain_info(test_ctx, attrs, false, &flat_name, &site, &forest);
    assert_int_equal(ret, EOK);
    assert_string_equal(flat_name, "AD");
    assert_null(site);
    assert_string_equal(forest, "ad.devel");

    talloc_free(flat_name);
    talloc_free(site);
    talloc_free(forest);
    ret = netlogon_get_domain_info(test_ctx, attrs, true, &flat_name, &site, &forest);
    assert_int_equal(ret, EOK);
    assert_string_equal(flat_name, "AD");
    assert_null(site);
    assert_string_equal(forest, "ad.devel");

    talloc_free(flat_name);
    talloc_free(site);
    talloc_free(forest);
    talloc_free(val.data);
    talloc_free(attrs);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int ret;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_ad_create_1way_trust_options,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_create_2way_trust_options,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_get_dom_ldap_conn,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_gc_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_ldap_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_user_conn_list,
                                        test_ldap_conn_setup,
                                        test_ldap_conn_teardown),
        cmocka_unit_test_setup_teardown(test_check_if_pac_is_available,
                                        test_ad_sysdb_setup,
                                        test_ad_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_ad_get_data_from_pac,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_get_sids_from_pac,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
#ifdef HAVE_STRUCT_PAC_LOGON_INFO_RESOURCE_GROUPS
        cmocka_unit_test_setup_teardown(test_ad_get_sids_from_pac_with_resource_groups,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
#endif
#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
        cmocka_unit_test_setup_teardown(test_ad_pac_with_has_sam_name_and_sid,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_ad_pac_missing_upn_dns_info,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
#endif
        cmocka_unit_test_setup_teardown(test_ad_get_pac_data_from_user_entry,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
        cmocka_unit_test_setup_teardown(test_netlogon_get_domain_info,
                                        test_ad_common_setup,
                                        test_ad_common_teardown),
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

    tests_set_cwd();

    ret = cmocka_run_group_tests(tests, NULL, NULL);

    return ret;
}
