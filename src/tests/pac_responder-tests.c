/*
    SSSD - Test for PAC reponder functions

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include <stdbool.h>
#include <math.h>
#include <util/data_blob.h>
#include <gen_ndr/security.h>

#include "tests/common.h"
#include "responder/pac/pacsrv.h"
#include "lib/idmap/sss_idmap.h"

struct dom_sid test_dom_sid = {1, 4, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 0,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const char *test_dom_sid_str = "S-1-5-21-2127521184-1604012920-1887927527";

struct dom_sid test_remote_dom_sid = {1, 4, {0, 0, 0, 0, 0, 5},
                                      {21, 123, 456, 789, 0,
                                       0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const char *test_remote_dom_sid_str = "S-1-5-21-123-456-789";

struct dom_sid test_smb_sid = {1, 5, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 1123,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const uint32_t test_id = 1200123;

struct dom_sid test_smb_sid_2nd = {1, 5, {0, 0, 0, 0, 0, 5},
                               {21, 2127521184, 1604012920, 1887927527, 201456,
                                0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};
const uint32_t test_id_2nd = 1200456;

struct local_mapping_ranges test_map = {{1200000, 1399999},
                                        {1000, 200999},
                                        {201000, 400999}};

static void *idmap_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void idmap_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

struct pac_ctx *pac_ctx;

#define IDMAP_RANGE_MIN 1234
#define IDMAP_RANGE_MAX 9876543

void pac_setup(void) {
    enum idmap_error_code err;
    struct sss_idmap_range remote_range = {IDMAP_RANGE_MIN, IDMAP_RANGE_MAX};
    struct sss_domain_info *sd;

    pac_ctx = talloc_zero(global_talloc_context, struct pac_ctx);
    fail_unless(pac_ctx != NULL, "talloc_zero failed.\n");

    pac_ctx->rctx = talloc_zero(pac_ctx, struct resp_ctx);
    fail_unless(pac_ctx->rctx != NULL, "talloc_zero failed.");

    pac_ctx->rctx->domains = talloc_zero(pac_ctx->rctx, struct sss_domain_info);
    fail_unless(pac_ctx->rctx->domains != NULL, "talloc_zero failed.");

    pac_ctx->rctx->domains->name = talloc_strdup(pac_ctx->rctx->domains,
                                                 "TEST.DOM");
    fail_unless(pac_ctx->rctx->domains->name != NULL, "talloc_strdup failed.");

    pac_ctx->rctx->domains->flat_name = talloc_strdup(pac_ctx->rctx->domains,
                                                      "TESTDOM");
    fail_unless(pac_ctx->rctx->domains->flat_name != NULL,
                "talloc_strdup failed.");

    pac_ctx->rctx->domains->domain_id = talloc_strdup(pac_ctx->rctx->domains,
                                                      test_dom_sid_str);
    fail_unless(pac_ctx->rctx->domains->domain_id != NULL,
                "talloc_strdup failed.");

    pac_ctx->rctx->domains->subdomain_count = 1;
    pac_ctx->rctx->domains->subdomains = talloc_zero_array(pac_ctx->rctx->domains,
                                                       struct sss_domain_info *,
                                       pac_ctx->rctx->domains->subdomain_count);
    fail_unless(pac_ctx->rctx->domains->subdomains != NULL,
                "talloc_array_zero failed");

    sd = talloc_zero(pac_ctx->rctx->domains->subdomains,
                     struct sss_domain_info);
    fail_unless(sd != NULL, "talloc_zero failed.");

    sd->name = talloc_strdup(sd, "remote.dom");
    fail_unless(sd->name != NULL, "talloc_strdup failed");

    sd->flat_name = talloc_strdup(sd, "REMOTEDOM");
    fail_unless(sd->flat_name != NULL, "talloc_strdup failed");

    sd->domain_id = talloc_strdup(sd, test_remote_dom_sid_str);
    fail_unless(sd->domain_id != NULL, "talloc_strdup failed");

    pac_ctx->rctx->domains->subdomains[0] = sd;

    err = sss_idmap_init(idmap_talloc, pac_ctx, idmap_talloc_free,
                         &pac_ctx->idmap_ctx);

    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    fail_unless(pac_ctx->idmap_ctx != NULL, "sss_idmap_init returned NULL.");

    err = sss_idmap_add_domain(pac_ctx->idmap_ctx, "remote.dom",
                               test_remote_dom_sid_str, &remote_range);

    pac_ctx->my_dom_sid = &test_dom_sid;

    pac_ctx->range_map = &test_map;
}

void pac_teardown(void)
{
    talloc_free(pac_ctx);
}


START_TEST(pac_test_local_sid_to_id)
{
    int ret;
    uint32_t id;

    ret = local_sid_to_id(&test_map, &test_smb_sid, &id);
    fail_unless(ret == EOK,
                "Failed to convert local sid to id.");
    fail_unless(id == test_id, "Wrong id returne, expected [%d], got [%d].",
                               test_id, id);
}
END_TEST

START_TEST(pac_test_seondary_local_sid_to_id)
{
    int ret;
    uint32_t id;

    ret = local_sid_to_id(&test_map, &test_smb_sid_2nd, &id);
    fail_unless(ret == EOK,
                "Failed to convert local sid to id.");
    fail_unless(id == test_id_2nd, "Wrong id returne, expected [%d], got [%d].",
                               test_id_2nd, id);
}
END_TEST

START_TEST(pac_test_get_gids_to_add_and_remove)
{
    TALLOC_CTX *mem_ctx;
    int ret;
    size_t c;
    size_t add_gid_count = 0;
    struct pac_dom_grps *add_gids = NULL;
    size_t del_gid_count = 0;
    struct grp_info **del_gids = NULL;
    struct sss_domain_info grp_dom;

    memset(&grp_dom, 0, sizeof(grp_dom));

    gid_t gid_list_2[] = {2};
    gid_t gid_list_3[] = {3};
    gid_t gid_list_23[] = {2, 3};
    struct pac_dom_grps empty_dom = {NULL, 0, NULL};

    struct pac_dom_grps pac_grp_2 = {&grp_dom, 1, gid_list_2};
    struct pac_dom_grps pac_grp_3 = {&grp_dom, 1, gid_list_3};
    struct pac_dom_grps pac_grp_23 = {&grp_dom, 2, gid_list_23};

    struct pac_dom_grps dom_grp_list_2[] = {pac_grp_2, empty_dom};
    struct pac_dom_grps dom_grp_list_3[] = {pac_grp_3, empty_dom};
    struct pac_dom_grps dom_grp_list_23[] = {pac_grp_23, empty_dom};

    struct grp_info grp_info_1 = {1, NULL, NULL};
    struct grp_info grp_info_2 = {2, NULL, NULL};
    struct grp_info  grp_list_1[] = {grp_info_1};
    struct grp_info  grp_list_12[] = {grp_info_1, grp_info_2};

    struct a_and_r_data {
        size_t cur_gid_count;
        struct grp_info *cur_gids;
        size_t gid_count;
        struct pac_dom_grps *gids;
        int exp_ret;
        size_t exp_add_gid_count;
        struct pac_dom_grps *exp_add_gids;
        size_t exp_del_gid_count;
        struct grp_info *exp_del_gids;
    } a_and_r_data[] = {
            {1, grp_list_1, 1, dom_grp_list_2, EOK, 1, dom_grp_list_2, 1, grp_list_1},
            {1, grp_list_1, 0, NULL, EOK, 0, NULL, 1, grp_list_1},
            {0, NULL, 1, dom_grp_list_2, EOK, 1, dom_grp_list_2, 0, NULL},
            {2, grp_list_12, 1, dom_grp_list_2, EOK,  0, NULL, 1, grp_list_1},
            {2, grp_list_12, 2, dom_grp_list_23, EOK, 1, dom_grp_list_3, 1, grp_list_1},
            {0, NULL, 0, NULL, 0, 0, NULL, 0, NULL}
    };

    mem_ctx = talloc_new(NULL);
    fail_unless(mem_ctx != NULL, "talloc_new failed.");

    ret = diff_gid_lists(mem_ctx, 0, NULL, 0, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EOK, "get_gids_to_add_and_remove failed with empty " \
                            "groups.");

    ret = diff_gid_lists(mem_ctx, 1, NULL, 0, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EINVAL, "get_gids_to_add_and_remove failed with " \
                               "invalid current groups.");

    ret = diff_gid_lists(mem_ctx, 0, NULL, 1, NULL,
                         &add_gid_count, &add_gids,
                         &del_gid_count, &del_gids);
    fail_unless(ret == EINVAL, "get_gids_to_add_and_remove failed with " \
                               "invalid new groups.");

    for (c = 0; a_and_r_data[c].cur_gids != NULL ||
                a_and_r_data[c].gids != NULL; c++) {
        ret = diff_gid_lists(mem_ctx,
                             a_and_r_data[c].cur_gid_count,
                             a_and_r_data[c].cur_gids,
                             a_and_r_data[c].gid_count,
                             a_and_r_data[c].gids,
                             &add_gid_count, &add_gids,
                             &del_gid_count, &del_gids);
        fail_unless(ret == a_and_r_data[c].exp_ret,
                    "Unexpected return value for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_ret, ret);
        fail_unless(add_gid_count ==  a_and_r_data[c].exp_add_gid_count,
                    "Unexpected numer of groups to add for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_add_gid_count, add_gid_count);
        fail_unless(del_gid_count ==  a_and_r_data[c].exp_del_gid_count,
                    "Unexpected numer of groups to delete for test data #%d, " \
                    "expected [%d], got [%d]",
                    c, a_and_r_data[c].exp_del_gid_count, del_gid_count);

        /* The lists might be returned in any order, to make tests simple we
         * only look at lists with 1 element. TODO: add code to compare lists
         * with more than 1 member. */
        if (add_gid_count == 1) {
            fail_unless(add_gids[0].gids[0] ==  a_and_r_data[c].exp_add_gids[0].gids[0],
                        "Unexpected gid to add for test data #%d, " \
                        "expected [%d], got [%d]",
                        c, a_and_r_data[c].exp_add_gids[0].gids[0], add_gids[0].gids[0]);
        }

        if (del_gid_count == 1) {
            fail_unless(del_gids[0]->gid == a_and_r_data[c].exp_del_gids[0].gid,
                        "Unexpected gid to delete for test data #%d, " \
                        "expected [%d], got [%d]",
                        c, a_and_r_data[c].exp_del_gids[0].gid,
                        del_gids[0]->gid);
        }
    }

    talloc_free(mem_ctx);
}
END_TEST

#define NUM_DOMAINS 10
START_TEST(pac_test_find_domain_by_id)
{
    struct sss_domain_info *dom;
    struct sss_domain_info **domains;
    size_t c;
    char *id;

    dom = find_domain_by_id(NULL, NULL);
    fail_unless(dom == NULL, "Domain returned without any input.");

    dom = find_domain_by_id(NULL, "id");
    fail_unless(dom == NULL, "Domain returned without domain list.");

    domains = talloc_zero_array(global_talloc_context, struct sss_domain_info *,
                                NUM_DOMAINS);
    for (c = 0; c < NUM_DOMAINS; c++) {
        domains[c] = talloc_zero(domains, struct sss_domain_info);
        fail_unless(domains[c] != NULL, "talloc_zero failed.");

        domains[c]->domain_id = talloc_asprintf(domains[c],
                                                "ID-of-domains-%zu", c);
        fail_unless(domains[c]->domain_id != NULL, "talloc_asprintf failed.");
        if (c > 0) {
            domains[c-1]->next = domains[c];
        }
    }

    dom = find_domain_by_id(domains[0], NULL);
    fail_unless(dom == NULL, "Domain returned without search domain.");

    dom = find_domain_by_id(domains[0], "DOES-NOT_EXISTS");
    fail_unless(dom == NULL, "Domain returned with non existing id.");

    for (c = 0; c < NUM_DOMAINS; c++) {
        id = talloc_asprintf(global_talloc_context, "ID-of-domains-%zu", c);
        fail_unless(id != NULL, "talloc_asprintf failed.\n");

        dom = find_domain_by_id(domains[0], id);
        fail_unless(dom == domains[c], "Wrong domain returned for id [%s].",
                                       id);

        talloc_free(id);
    }

    talloc_free(domains);
}
END_TEST

START_TEST(pac_test_get_gids_from_pac)
{
    int ret;
    size_t c;
    size_t d;
    size_t g;
    size_t t;
    size_t gid_count;
    struct pac_dom_grps *gids;
    struct PAC_LOGON_INFO *logon_info;
    bool found;
    gid_t exp_gid;
    struct timeval start_time;
    struct timeval end_time;
    struct timeval diff_time;

    ret = get_gids_from_pac(NULL, NULL, NULL, NULL, NULL, NULL, NULL);
    fail_unless(ret == EINVAL, "Unexpected return value for NULL parameters");

    logon_info = talloc_zero(global_talloc_context, struct PAC_LOGON_INFO);
    fail_unless(logon_info != NULL, "talloc_zero failed.\n");

    ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                            pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
    fail_unless(ret == EOK, "Failed with empty PAC");
    fail_unless(gid_count == 0, "O groups expected, got [%d]", gid_count);
    fail_unless(gids == NULL, "Expected NULL gid array.");

    logon_info->info3.base.domain_sid = &test_smb_sid_2nd; /* unknown SID */
    logon_info->info3.base.groups.count = 10;
    logon_info->info3.base.groups.rids = talloc_array(logon_info,
                                           struct samr_RidWithAttribute,
                                           logon_info->info3.base.groups.count);
    fail_unless(logon_info->info3.base.groups.rids != NULL, "talloc_array failed.");

    for (c = 0; c < logon_info->info3.base.groups.count; c++) {
        logon_info->info3.base.groups.rids[c].rid = 500 + c;
    }

    ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                            pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
    fail_unless(ret == EINVAL, "Unexpected return code [%d] with unknown SID.",
                               ret);

    /* change SID to a known one */
    logon_info->info3.base.domain_sid = &test_remote_dom_sid;

    ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                            pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
    fail_unless(ret == EOK, "Failed with 10 RIDs in PAC");
    fail_unless(gid_count == logon_info->info3.base.groups.count,
                "[%d] groups expected, got [%d]",
                logon_info->info3.base.groups.count, gid_count);
    fail_unless(gids != NULL, "Expected gid array.");

    for (c = 0; c < logon_info->info3.base.groups.count; c++) {
        found = false;
        exp_gid = IDMAP_RANGE_MIN + 500 + c;
        for (g = 0; g < gid_count; g++) {
            if (gids[1].gids[g] == exp_gid) {
                found = true;
                break;
            }
        }
        fail_unless(found, "[%d] not found in group list", exp_gid);
    }

    talloc_free(gids);
    gids = NULL;

    /* duplicated RIDs */
    for (c = 0; c < logon_info->info3.base.groups.count; c++) {
        logon_info->info3.base.groups.rids[c].rid = 500;
    }

    ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                            pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
    fail_unless(ret == EOK, "Failed with 10 duplicated RIDs in PAC");
    fail_unless(gid_count == 1, "[%d] groups expected, got [%d]", 1, gid_count);
    fail_unless(gids != NULL, "Expected gid array.");
    fail_unless(gids[1].gids[0] == IDMAP_RANGE_MIN + 500,
                "Wrong gid returned, got [%d], expected [%d].", gids[1].gids[0],
                                                         IDMAP_RANGE_MIN + 500);
    talloc_free(gids);
    gids = NULL;

    logon_info->info3.sidcount = 2;
    logon_info->info3.sids = talloc_zero_array(logon_info, struct netr_SidAttr,
                                               logon_info->info3.sidcount);
    fail_unless(logon_info->info3.sids != NULL, "talloc_zero_array failed.");

    logon_info->info3.sids[0].sid = &test_smb_sid;
    logon_info->info3.sids[1].sid = &test_smb_sid_2nd;

    ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                            pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
    fail_unless(ret == EOK, "Failed with 10 duplicated RIDs and local SIDS in PAC");
    fail_unless(gid_count == 3, "[%d] groups expected, got [%d]", 3, gid_count);
    fail_unless(gids != NULL, "Expected gid array.");

    gid_t exp_gids[] = {IDMAP_RANGE_MIN + 500, test_id, test_id_2nd, 0};

    for (c = 0; exp_gids[c] != 0; c++) {
        found = false;
        for (d = 0; d < 2; d++) {
            for (g = 0; g < gids[d].gid_count; g++) {
                if (gids[d].gids[g] == exp_gids[c]) {
                    found = true;
                    break;
                }
            }
            if (found) {
                break;
            }
        }
        fail_unless(found, "[%d] not found in group list", exp_gids[c]);
    }

    talloc_free(gids);
    gids = NULL;

    talloc_free(logon_info->info3.base.groups.rids);

    for (t = 0; t < 7; t++) {
        logon_info->info3.base.groups.count = powl(10, t);
        logon_info->info3.base.groups.rids = talloc_array(logon_info,
                                               struct samr_RidWithAttribute,
                                               logon_info->info3.base.groups.count);
        fail_unless(logon_info->info3.base.groups.rids != NULL, "talloc_array failed.");

        for (c = 0; c < logon_info->info3.base.groups.count; c++) {
            logon_info->info3.base.groups.rids[c].rid = 500 + c;
        }

        ret = gettimeofday(&start_time, NULL);
        fail_unless(ret == 0, "gettimeofday failed.");

        ret = get_gids_from_pac(global_talloc_context, pac_ctx, pac_ctx->range_map,
                                pac_ctx->my_dom_sid, logon_info, &gid_count, &gids);
        fail_unless(ret == EOK, "Unexpected return code [%d].", ret);

        ret = gettimeofday(&end_time, NULL);
        fail_unless(ret == 0, "gettimeofday failed.");

        timersub(&end_time, &start_time, &diff_time);
        fprintf(stderr, "Testcase [%zu], number of groups [%u], " \
                        "duration [%ds %dus]\n", t,
                        logon_info->info3.base.groups.count,
                        (int) diff_time.tv_sec,
                        (int) diff_time.tv_usec);

        talloc_free(gids);
        gids = NULL;

        talloc_free(logon_info->info3.base.groups.rids);
    }

    talloc_free(logon_info);
}
END_TEST

Suite *idmap_test_suite (void)
{
    Suite *s = suite_create ("PAC responder");

    TCase *tc_pac = tcase_create("PAC responder tests");
    tcase_add_checked_fixture(tc_pac,
                              leak_check_setup,
                              leak_check_teardown);

    tcase_add_checked_fixture(tc_pac,
                              pac_setup,
                              pac_teardown);

    tcase_add_test(tc_pac, pac_test_local_sid_to_id);
    tcase_add_test(tc_pac, pac_test_seondary_local_sid_to_id);
    tcase_add_test(tc_pac, pac_test_get_gids_to_add_and_remove);
    tcase_add_test(tc_pac, pac_test_find_domain_by_id);
    tcase_add_test(tc_pac, pac_test_get_gids_from_pac);

    suite_add_tcase(s, tc_pac);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = idmap_test_suite();
    SRunner *sr = srunner_create(s);

    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed (sr);
    srunner_free (sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
