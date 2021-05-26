/*
    SSSD - Test for idmap library

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

#include "lib/idmap/sss_idmap.h"
#include "lib/idmap/sss_idmap_private.h"
#include "tests/common_check.h"

#define IDMAP_RANGE_MIN 1234
#define IDMAP_RANGE_MAX 9876

#define IDMAP_RANGE_MIN2 11234
#define IDMAP_RANGE_MAX2 19876

const char test_sid[] = "S-1-5-21-2127521184-1604012920-1887927527-72713";
uint8_t test_bin_sid[] = {0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15,
                          0x00, 0x00, 0x00, 0xA0, 0x65, 0xCF, 0x7E, 0x78, 0x4B,
                          0x9B, 0x5F, 0xE7, 0x7C, 0x87, 0x70, 0x09, 0x1C, 0x01,
                          0x00};
size_t test_bin_sid_length = sizeof(test_bin_sid);

struct dom_sid test_smb_sid = {1, 5, {0, 0, 0, 0, 0, 5}, {21, 2127521184, 1604012920, 1887927527, 72713, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}};

const char large_sid[] = "S-1-5-21-1-2-4294967295-1000";
const char too_large_sid[] = "S-1-5-21-1-2-4294967296-1000";

struct sss_idmap_ctx *idmap_ctx;

static void *idmap_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void idmap_talloc_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}


void idmap_ctx_setup(void)
{
    enum idmap_error_code err;

    err = sss_idmap_init(idmap_talloc, global_talloc_context, idmap_talloc_free,
                         &idmap_ctx);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    ck_assert_msg(idmap_ctx != NULL, "sss_idmap_init returned NULL.");
}

void idmap_ctx_setup_additional_secondary_slices(void)
{
    enum idmap_error_code err;

    err = sss_idmap_init(idmap_talloc, global_talloc_context, idmap_talloc_free,
                         &idmap_ctx);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    ck_assert_msg(idmap_ctx != NULL, "sss_idmap_init returned NULL.");

    idmap_ctx->idmap_opts.rangesize = 10;
    idmap_ctx->idmap_opts.extra_slice_init = 5;
}

void idmap_ctx_teardown(void)
{
    enum idmap_error_code err;

    err = sss_idmap_free(idmap_ctx);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}

void idmap_add_domain_setup(void)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {IDMAP_RANGE_MIN, IDMAP_RANGE_MAX};

    err = sss_idmap_add_domain(idmap_ctx, "test.dom", "S-1-5-21-1-2-3", &range);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_domain failed.");
}

void idmap_add_domain_with_sec_slices_setup(void)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {
        IDMAP_RANGE_MIN,
        IDMAP_RANGE_MIN + idmap_ctx->idmap_opts.rangesize - 1,
    };

    err = sss_idmap_add_auto_domain_ex(idmap_ctx, "test.dom", "S-1-5-21-1-2-3",
                                       &range, NULL, 0, false, NULL, NULL);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_auto_domain_ex failed.");
}


enum idmap_error_code cb(const char *dom_name,
                         const char *dom_sid,
                         const char *range_id,
                         uint32_t min_id,
                         uint32_t max_id,
                         uint32_t first_rid,
                         void *pvt)
{
    return IDMAP_ERROR;
}

void idmap_add_domain_with_sec_slices_setup_cb_fail(void)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {
        IDMAP_RANGE_MIN,
        IDMAP_RANGE_MIN + idmap_ctx->idmap_opts.rangesize - 1,
    };

    err = sss_idmap_add_auto_domain_ex(idmap_ctx, "test.dom", "S-1-5-21-1-2-3",
                                       &range, NULL, 0, false, cb, NULL);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_auto_domain_ex failed.");
}


#define DATA_MAX 1000
char data[DATA_MAX];

enum idmap_error_code cb2(const char *dom_name,
                          const char *dom_sid,
                          const char *range_id,
                          uint32_t min_id,
                          uint32_t max_id,
                          uint32_t first_rid,
                          void *pvt)
{
    char *p = (char*)pvt;
    size_t len;

    len = snprintf(p, DATA_MAX, "%s, %s %s, %"PRIu32", %"PRIu32", %" PRIu32,
                   dom_name, dom_sid, range_id, min_id, max_id, first_rid);

    if (len >= DATA_MAX) {
        return IDMAP_OUT_OF_MEMORY;
    }
    return IDMAP_SUCCESS;
}

void idmap_add_domain_with_sec_slices_setup_cb_ok(void)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {
        IDMAP_RANGE_MIN,
        IDMAP_RANGE_MIN + idmap_ctx->idmap_opts.rangesize - 1,
    };

    void *pvt = (void*) data;

    err = sss_idmap_add_auto_domain_ex(idmap_ctx, "test.dom", "S-1-5-21-1-2-3",
                                       &range, NULL, 0, false, cb2, pvt);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_auto_domain_ex failed.");
}

START_TEST(idmap_test_is_domain_sid)
{
    size_t c;
    const char *invalid[] = { "abc",
                              "S-1-2-3-4-5-6",
                              "S-1-5-21-1",
                              "S-1-5-21-1-2-123456789012345678",
                              "S-1-5-21-1+2+3",
                              "S-1-5-21-a-b-c",
                              "S-1-5-21-1-2-3-4",
                              NULL };

    sss_ck_fail_if_msg(is_domain_sid(NULL), "is_domain_sid() returned true for [NULL]");
    for (c = 0; invalid[c] != NULL; c++) {
        sss_ck_fail_if_msg(is_domain_sid(invalid[c]),
                "is_domain_sid() returned true for [%s]", invalid[c]);
    }

    ck_assert_msg(is_domain_sid("S-1-5-21-1-2-3"),
                "is_domain_sid() returned true for [S-1-5-21-1-2-3]");
}
END_TEST

START_TEST(idmap_test_init_malloc)
{
    enum idmap_error_code err;
    struct sss_idmap_ctx *ctx = NULL;

    err = sss_idmap_init(NULL, NULL, NULL, &ctx);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    ck_assert_msg(ctx != NULL, "sss_idmap_init returned NULL.");

    err = sss_idmap_free(ctx);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}
END_TEST

START_TEST(idmap_test_init_talloc)
{
    enum idmap_error_code err;
    struct sss_idmap_ctx *ctx = NULL;

    err = sss_idmap_init(idmap_talloc, global_talloc_context, idmap_talloc_free,
                         &ctx);

    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    ck_assert_msg(ctx != NULL, "sss_idmap_init returned NULL.");

    err = sss_idmap_free(ctx);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}
END_TEST

START_TEST(idmap_test_add_domain)
{
    idmap_add_domain_setup();
}
END_TEST

START_TEST(idmap_test_add_domain_collisions)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {IDMAP_RANGE_MIN, IDMAP_RANGE_MAX};
    struct sss_idmap_range range2 = {IDMAP_RANGE_MIN2, IDMAP_RANGE_MAX2};

    err = sss_idmap_add_domain(idmap_ctx, "test.dom", "S-1-5-21-1-2-3", &range);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_domain failed.");

    err = sss_idmap_add_domain(idmap_ctx, "test.dom", "S-1-5-21-1-2-4",
                               &range2);
    ck_assert_msg(err == IDMAP_COLLISION,
                "sss_idmap_add_domain added domain with the same name.");

    err = sss_idmap_add_domain(idmap_ctx, "test.dom2", "S-1-5-21-1-2-3",
                               &range2);
    ck_assert_msg(err == IDMAP_COLLISION,
                "sss_idmap_add_domain added domain with the same SID.");

    err = sss_idmap_add_domain(idmap_ctx, "test.dom2", "S-1-5-21-1-2-4",
                               &range);
    ck_assert_msg(err == IDMAP_COLLISION,
                "sss_idmap_add_domain added domain with the same range.");

    err = sss_idmap_add_domain(idmap_ctx, "test.dom2", "S-1-5-21-1-2-4",
                               &range2);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "sss_idmap_add_domain failed to add second domain.");
}
END_TEST

START_TEST(idmap_test_add_domain_collisions_ext_mapping)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {IDMAP_RANGE_MIN, IDMAP_RANGE_MAX};
    struct sss_idmap_range range2 = {IDMAP_RANGE_MIN2, IDMAP_RANGE_MAX2};

    err = sss_idmap_add_domain_ex(idmap_ctx, "test.dom", "S-1-5-21-1-2-3",
                                  &range, NULL, 0, true);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_add_domain failed.");

    err = sss_idmap_add_domain_ex(idmap_ctx, "test.dom", "S-1-5-21-1-2-4",
                                  &range2, NULL, 0, true);
    ck_assert_msg(err == IDMAP_COLLISION,
                "sss_idmap_add_domain added domain with the same name.");

    err = sss_idmap_add_domain_ex(idmap_ctx, "test.dom2", "S-1-5-21-1-2-3",
                                  &range2, NULL, 0, true);
    ck_assert_msg(err == IDMAP_COLLISION,
                "sss_idmap_add_domain added domain with the same SID.");

    err = sss_idmap_add_domain_ex(idmap_ctx, "test.dom2", "S-1-5-21-1-2-4",
                                  &range, NULL, 0, true);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "sss_idmap_add_domain failed to add second domain with " \
                "external mapping and the same range.");
}
END_TEST

START_TEST(idmap_test_sid2uid)
{
    enum idmap_error_code err;
    uint32_t id;

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3333-1000", &id);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_sid_to_unix did not detect "
                                        "unknown domain");

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-10000", &id);
    ck_assert_msg(err == IDMAP_NO_RANGE, "sss_idmap_sid_to_unix did not detect "
                                       "RID out of range");

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-1000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    ck_assert_msg(id == (1000 + IDMAP_RANGE_MIN),
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, 1000 + IDMAP_RANGE_MIN);
}
END_TEST

START_TEST(idmap_test_sid2uid_ss)
{
    enum idmap_error_code err;
    uint32_t id;
    const uint32_t exp_id = 351800000;
    const uint32_t exp_id2 = 832610000;

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3333-1000", &id);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_sid_to_unix did not detect "
                                        "unknown domain");

    /* RID out of primary and secondary range */
    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-4000000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    ck_assert_msg(id == exp_id,
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, exp_id);

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-1000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    ck_assert_msg(id == (1000 + IDMAP_RANGE_MIN),
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, 1000 + IDMAP_RANGE_MIN);

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-210000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    ck_assert_msg(id == exp_id2,
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, exp_id2);
}
END_TEST

START_TEST(idmap_test_sid2uid_ext_sec_slices)
{
    enum idmap_error_code err;
    uint32_t id;
    char *sid;
    const uint32_t exp_id = 351800000;

    err = sss_idmap_unix_to_sid(idmap_ctx, exp_id, &sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    /* RID out of primary and secondary range */
    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-4000000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    ck_assert_msg(id == exp_id,
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, exp_id);

    /* Secondary ranges were expanded by sid_to_unix call */
    err = sss_idmap_unix_to_sid(idmap_ctx, exp_id, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_sid failed.");
    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-4000000") == 0,
                "sss_idmap_unix_to_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-4000000", sid);
    sss_idmap_free_sid(idmap_ctx, sid);
}
END_TEST


START_TEST(idmap_test_dyn_dom_store_cb_fail)
{
    enum idmap_error_code err;
    uint32_t id;
    char *sid;
    const uint32_t exp_id = 351800000;

    err = sss_idmap_unix_to_sid(idmap_ctx, exp_id, &sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    /* RID out of primary and secondary range */
    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-4000000", &id);
    ck_assert_msg(err == IDMAP_ERROR, "sss_idmap_sid_to_unix failed.");
}
END_TEST

START_TEST(idmap_test_dyn_dom_store_cb_ok)
{
    enum idmap_error_code err;
    uint32_t id;
    char *sid;
    const uint32_t exp_id = 351800000;
    const char *exp_stored_data = "test.dom, S-1-5-21-1-2-3 S-1-5-21-1-2-3-4000000, 351800000, 351999999, 4000000";

    err = sss_idmap_unix_to_sid(idmap_ctx, exp_id, &sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    /* RID out of primary and secondary range */
    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-4000000", &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");

    ck_assert_msg(strcmp(data,
                       exp_stored_data) == 0,
                "Storing dynamic domains idmapping failed: "
                "expected [%s] but got [%s].", exp_stored_data, data);
}
END_TEST


START_TEST(idmap_test_sid2uid_additional_secondary_slices)
{
    enum idmap_error_code err;
    struct TALLOC_CTX *tmp_ctx;
    const char *dom_prefix = "S-1-5-21-1-2-3";
    const int max_rid = 80;
    const char *sids[max_rid + 1];
    unsigned int ids[max_rid + 1];

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "Out of memory.");

    for (unsigned int i = 0; i < max_rid + 1; i++) {
        sids[i] = talloc_asprintf(tmp_ctx, "%s-%u", dom_prefix, i);

        ck_assert_msg(sids[i] != NULL, "Out of memory");

        err = sss_idmap_sid_to_unix(idmap_ctx, sids[i], &ids[i]);
        ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    }

    for (unsigned int i = 0; i < max_rid + 1; i++) {
        char *sid;

        err = sss_idmap_unix_to_sid(idmap_ctx, ids[i], &sid);
        ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");

        ck_assert_msg(strcmp(sid, sids[i]) == 0,
                    "sss_idmap_unix_to_sid returned wrong sid, "
                    "got [%s], expected [%s].", sid, sids[i]);
        talloc_free(sid);
    }

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(idmap_test_bin_sid2uid)
{
    enum idmap_error_code err;
    uint32_t id;
    uint8_t *bin_sid = NULL;
    size_t length;

    err = sss_idmap_sid_to_bin_sid(idmap_ctx, "S-1-5-21-1-2-3-1000",
                                   &bin_sid, &length);
    ck_assert_msg(err == IDMAP_SUCCESS, "Failed to convert SID to binary SID");

    err = sss_idmap_bin_sid_to_unix(idmap_ctx, bin_sid, length , &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_bin_sid_to_unix failed.");
    ck_assert_msg(id == (1000 + IDMAP_RANGE_MIN),
                "sss_idmap_bin_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, 1000 + IDMAP_RANGE_MIN);

    sss_idmap_free_bin_sid(idmap_ctx, bin_sid);
}
END_TEST

START_TEST(idmap_test_dom_sid2uid)
{
    enum idmap_error_code err;
    uint32_t id;
    struct sss_dom_sid *dom_sid = NULL;

    err = sss_idmap_sid_to_dom_sid(idmap_ctx, "S-1-5-21-1-2-3-1000", &dom_sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "Failed to convert SID to SID structure");

    err = sss_idmap_dom_sid_to_unix(idmap_ctx, dom_sid, &id);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_dom_sid_to_unix failed.");
    ck_assert_msg(id == (1000 + IDMAP_RANGE_MIN),
                "sss_idmap_dom_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, 1000 + IDMAP_RANGE_MIN);

    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
}
END_TEST

START_TEST(idmap_test_uid2sid)
{
    enum idmap_error_code err;
    char *sid;

    err = sss_idmap_unix_to_sid(idmap_ctx, 10000, &sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    err = sss_idmap_unix_to_sid(idmap_ctx, 2234, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_sid failed.");
    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-1000") == 0,
                "sss_idmap_unix_to_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-1000", sid);

    sss_idmap_free_sid(idmap_ctx, sid);
}
END_TEST

START_TEST(idmap_test_uid2sid_ss)
{
    enum idmap_error_code err;
    char *sid;

    err = sss_idmap_unix_to_sid(idmap_ctx,
                                IDMAP_RANGE_MIN + idmap_ctx->idmap_opts.rangesize + 1,
                                &sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    err = sss_idmap_unix_to_sid(idmap_ctx, 2234, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_sid failed.");
    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-1000") == 0,
                "sss_idmap_unix_to_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-1000", sid);

    sss_idmap_free_sid(idmap_ctx, sid);

    /* Secondary ranges */
    err = sss_idmap_unix_to_sid(idmap_ctx,
                                313800000,
                                &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_sid failed.");
    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-400000") == 0,
                "sss_idmap_unix_to_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-400000", sid);

    sss_idmap_free_sid(idmap_ctx, sid);
}
END_TEST

START_TEST(idmap_test_uid2dom_sid)
{
    enum idmap_error_code err;
    struct sss_dom_sid *dom_sid = NULL;
    char *sid = NULL;

    err = sss_idmap_unix_to_dom_sid(idmap_ctx, 10000, &dom_sid);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_dom_sid did not detect "
                                        "id out of range");

    err = sss_idmap_unix_to_dom_sid(idmap_ctx, 2234, &dom_sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_dom_sid failed.");

    err = sss_idmap_dom_sid_to_sid(idmap_ctx, dom_sid, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_dom_sid_to_sid failed.");

    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-1000") == 0,
                "sss_idmap_unix_to_dom_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-1000", sid);

    sss_idmap_free_sid(idmap_ctx, sid);
    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
}
END_TEST

START_TEST(idmap_test_uid2bin_sid)
{
    enum idmap_error_code err;
    uint8_t *bin_sid = NULL;
    size_t length;
    char *sid = NULL;

    err = sss_idmap_unix_to_bin_sid(idmap_ctx, 10000, &bin_sid, &length);
    ck_assert_msg(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_bin_sid did not detect "
                                        "id out of range");

    err = sss_idmap_unix_to_bin_sid(idmap_ctx, 2234, &bin_sid, &length);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_unix_to_bin_sid failed.");

    err = sss_idmap_bin_sid_to_sid(idmap_ctx, bin_sid, length, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS, "sss_idmap_bin_sid_to_sid failed.");

    ck_assert_msg(strcmp(sid, "S-1-5-21-1-2-3-1000") == 0,
                "sss_idmap_unix_to_bin_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-1000", sid);

    sss_idmap_free_sid(idmap_ctx, sid);
    sss_idmap_free_bin_sid(idmap_ctx, bin_sid);
}
END_TEST

START_TEST(idmap_test_bin_sid2dom_sid)
{
    struct sss_dom_sid *dom_sid = NULL;
    enum idmap_error_code err;
    uint8_t *new_bin_sid = NULL;
    size_t new_bin_sid_length;

    err = sss_idmap_bin_sid_to_dom_sid(idmap_ctx, test_bin_sid,
                                       test_bin_sid_length, &dom_sid);

    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert binary SID to struct sss_dom_sid.");

    err = sss_idmap_dom_sid_to_bin_sid(idmap_ctx, dom_sid, &new_bin_sid,
                                       &new_bin_sid_length);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert struct sss_dom_sid to binary SID.");

    ck_assert_msg(new_bin_sid_length == test_bin_sid_length,
                "Length of binary SIDs do not match.");
    ck_assert_msg(memcmp(test_bin_sid, new_bin_sid, test_bin_sid_length) == 0,
                "Binary SIDs do not match.");

    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
    sss_idmap_free_bin_sid(idmap_ctx, new_bin_sid);
}
END_TEST

START_TEST(idmap_test_sid2dom_sid)
{
    struct sss_dom_sid *dom_sid = NULL;
    enum idmap_error_code err;
    char *new_sid = NULL;

    err = sss_idmap_sid_to_dom_sid(idmap_ctx, "S-1-5-21-1-2-3-1000", &dom_sid);

    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert SID string to struct sss_dom_sid.");

    err = sss_idmap_dom_sid_to_sid(idmap_ctx, dom_sid, &new_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert struct sss_dom_sid to SID string.");

    ck_assert_msg(new_sid != NULL, "SID string not set");
    ck_assert_msg(strlen("S-1-5-21-1-2-3-1000") == strlen(new_sid),
                "Length of SID strings do not match.");
    ck_assert_msg(strcmp("S-1-5-21-1-2-3-1000", new_sid) == 0,
                "SID strings do not match.");

    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
    sss_idmap_free_sid(idmap_ctx, new_sid);
}
END_TEST

START_TEST(idmap_test_large_and_too_large_sid)
{
    struct sss_dom_sid *dom_sid = NULL;
    enum idmap_error_code err;
    char *new_sid = NULL;

    err = sss_idmap_sid_to_dom_sid(idmap_ctx, large_sid, &dom_sid);

    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert SID string with a UINT32_MAX component "
                "to struct sss_dom_sid.");

    err = sss_idmap_dom_sid_to_sid(idmap_ctx, dom_sid, &new_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert struct sss_dom_sid to SID string.");

    ck_assert_msg(new_sid != NULL, "SID string not set");
    ck_assert_msg(strlen(large_sid) == strlen(new_sid),
                "Length of SID strings do not match.");
    ck_assert_msg(strcmp(large_sid, new_sid) == 0,
                "SID strings do not match, expected [%s], got [%s]",
                large_sid, new_sid);

    err = sss_idmap_sid_to_dom_sid(idmap_ctx, too_large_sid, &dom_sid);
    ck_assert_msg(err == IDMAP_SID_INVALID,
                "Trying to convert  a SID with a too large component "
                "did not return IDMAP_SID_INVALID");

    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
    sss_idmap_free_sid(idmap_ctx, new_sid);
}
END_TEST

START_TEST(idmap_test_sid2bin_sid)
{
    enum idmap_error_code err;
    size_t length;
    uint8_t *bin_sid = NULL;

    err = sss_idmap_sid_to_bin_sid(idmap_ctx, test_sid, &bin_sid, &length);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert SID string to binary sid.");
    ck_assert_msg(length == test_bin_sid_length,
                "Size of binary SIDs do not match, got [%zu], expected [%zu]",
                length, test_bin_sid_length);
    ck_assert_msg(memcmp(bin_sid, test_bin_sid, test_bin_sid_length) == 0,
                "Binary SIDs do not match");

    sss_idmap_free_bin_sid(idmap_ctx, bin_sid);
}
END_TEST

START_TEST(idmap_test_bin_sid2sid)
{
    enum idmap_error_code err;
    char *sid = NULL;

    err = sss_idmap_bin_sid_to_sid(idmap_ctx, test_bin_sid, test_bin_sid_length,
                                   &sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert binary SID to SID string.");
    ck_assert_msg(strcmp(sid, test_sid) == 0, "SID strings do not match, "
                                            "expected [%s], get [%s]",
                                            test_sid, sid);

    sss_idmap_free_sid(idmap_ctx, sid);
}
END_TEST

START_TEST(idmap_test_smb_sid2dom_sid)
{
    struct sss_dom_sid *dom_sid = NULL;
    enum idmap_error_code err;
    struct dom_sid *new_smb_sid = NULL;

    err = sss_idmap_smb_sid_to_dom_sid(idmap_ctx, &test_smb_sid, &dom_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert samba dom_sid to struct sss_dom_sid.");

    err = sss_idmap_dom_sid_to_smb_sid(idmap_ctx, dom_sid, &new_smb_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert struct sss_dom_sid to samba dom_sid.");

    ck_assert_msg(memcmp(&test_smb_sid, new_smb_sid, sizeof(struct dom_sid)) == 0,
                "Samba dom_sid-s do not match.");

    sss_idmap_free_dom_sid(idmap_ctx, dom_sid);
    sss_idmap_free_smb_sid(idmap_ctx, new_smb_sid);
}
END_TEST

START_TEST(idmap_test_smb_sid2bin_sid)
{
    enum idmap_error_code err;
    size_t length;
    uint8_t *bin_sid = NULL;

    err = sss_idmap_smb_sid_to_bin_sid(idmap_ctx, &test_smb_sid,
                                       &bin_sid, &length);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert samba dom_sid to binary sid.");
    ck_assert_msg(length == test_bin_sid_length,
                "Size of binary SIDs do not match, got [%zu], expected [%zu]",
                length, test_bin_sid_length);
    ck_assert_msg(memcmp(bin_sid, test_bin_sid, test_bin_sid_length) == 0,
                "Binary SIDs do not match.");

    sss_idmap_free_bin_sid(idmap_ctx, bin_sid);
}
END_TEST

START_TEST(idmap_test_bin_sid2smb_sid)
{
    enum idmap_error_code err;
    struct dom_sid *smb_sid = NULL;

    err = sss_idmap_bin_sid_to_smb_sid(idmap_ctx, test_bin_sid,
                                       test_bin_sid_length, &smb_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert binary sid to samba dom_sid.");
    ck_assert_msg(memcmp(&test_smb_sid, smb_sid, sizeof(struct dom_sid)) == 0,
                 "Samba dom_sid structs do not match.");

    sss_idmap_free_smb_sid(idmap_ctx, smb_sid);
}
END_TEST

START_TEST(idmap_test_smb_sid2sid)
{
    enum idmap_error_code err;
    char *sid = NULL;

    err = sss_idmap_smb_sid_to_sid(idmap_ctx, &test_smb_sid, &sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert samba dom_sid to sid string.");
    ck_assert_msg(strcmp(sid, test_sid) == 0, "SID strings do not match, "
                                            "expected [%s], get [%s]",
                                            test_sid, sid);

    sss_idmap_free_sid(idmap_ctx, sid);
}
END_TEST

START_TEST(idmap_test_sid2smb_sid)
{
    enum idmap_error_code err;
    struct dom_sid *smb_sid = NULL;

    err = sss_idmap_sid_to_smb_sid(idmap_ctx, test_sid, &smb_sid);
    ck_assert_msg(err == IDMAP_SUCCESS,
                "Failed to convert binary sid to samba dom_sid.");
    ck_assert_msg(memcmp(&test_smb_sid, smb_sid, sizeof(struct dom_sid)) == 0,
                 "Samba dom_sid structs do not match.");

    sss_idmap_free_smb_sid(idmap_ctx, smb_sid);
}
END_TEST


Suite *idmap_test_suite (void)
{
    Suite *s = suite_create ("IDMAP");

    TCase *tc_init = tcase_create("IDMAP init tests");
    tcase_add_checked_fixture(tc_init,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);

    tcase_add_test(tc_init, idmap_test_init_malloc);
    tcase_add_test(tc_init, idmap_test_init_talloc);
    tcase_add_test(tc_init, idmap_test_is_domain_sid);

    suite_add_tcase(s, tc_init);

    TCase *tc_dom = tcase_create("IDMAP domain tests");
    tcase_add_checked_fixture(tc_dom,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_dom,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);

    tcase_add_test(tc_dom, idmap_test_add_domain);
    tcase_add_test(tc_dom, idmap_test_add_domain_collisions);
    tcase_add_test(tc_dom, idmap_test_add_domain_collisions_ext_mapping);

    suite_add_tcase(s, tc_dom);

    TCase *tc_conv = tcase_create("IDMAP SID conversion tests");
    tcase_add_checked_fixture(tc_conv,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_conv,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);

    tcase_add_test(tc_conv, idmap_test_bin_sid2dom_sid);
    tcase_add_test(tc_conv, idmap_test_sid2dom_sid);
    tcase_add_test(tc_conv, idmap_test_sid2bin_sid);
    tcase_add_test(tc_conv, idmap_test_bin_sid2sid);
    tcase_add_test(tc_conv, idmap_test_smb_sid2dom_sid);
    tcase_add_test(tc_conv, idmap_test_smb_sid2bin_sid);
    tcase_add_test(tc_conv, idmap_test_bin_sid2smb_sid);
    tcase_add_test(tc_conv, idmap_test_smb_sid2sid);
    tcase_add_test(tc_conv, idmap_test_sid2smb_sid);
    tcase_add_test(tc_conv, idmap_test_large_and_too_large_sid);

    suite_add_tcase(s, tc_conv);

    TCase *tc_map = tcase_create("IDMAP mapping tests");
    tcase_add_checked_fixture(tc_map,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_map,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map,
                              idmap_add_domain_setup,
                              NULL);

    tcase_add_test(tc_map, idmap_test_sid2uid);
    tcase_add_test(tc_map, idmap_test_bin_sid2uid);
    tcase_add_test(tc_map, idmap_test_dom_sid2uid);
    tcase_add_test(tc_map, idmap_test_uid2sid);
    tcase_add_test(tc_map, idmap_test_uid2dom_sid);
    tcase_add_test(tc_map, idmap_test_uid2bin_sid);

    suite_add_tcase(s, tc_map);

    /* Test secondary slices */
    TCase *tc_map_ss = tcase_create("IDMAP mapping tests");
    tcase_add_checked_fixture(tc_map_ss,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_map_ss,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map_ss,
                              idmap_add_domain_with_sec_slices_setup,
                              NULL);

    tcase_add_test(tc_map_ss, idmap_test_sid2uid_ss);
    tcase_add_test(tc_map_ss, idmap_test_uid2sid_ss);
    tcase_add_test(tc_map_ss, idmap_test_sid2uid_ext_sec_slices);

    suite_add_tcase(s, tc_map_ss);

    /* Test secondary slices - callback to store failed. */
    TCase *tc_map_cb_fail = tcase_create("IDMAP mapping tests - store fail");
    tcase_add_checked_fixture(tc_map_cb_fail,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_map_cb_fail,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map_cb_fail,
                              idmap_add_domain_with_sec_slices_setup_cb_fail,
                              NULL);

    tcase_add_test(tc_map_cb_fail, idmap_test_dyn_dom_store_cb_fail);
    suite_add_tcase(s, tc_map_cb_fail);

    /* Test secondary slices - callback to store passed. */
    TCase *tc_map_cb_ok = tcase_create("IDMAP mapping tests");
    tcase_add_checked_fixture(tc_map_cb_ok,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_map_cb_ok,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map_cb_ok,
                              idmap_add_domain_with_sec_slices_setup_cb_ok,
                              NULL);

    tcase_add_test(tc_map_cb_ok, idmap_test_dyn_dom_store_cb_ok);
    suite_add_tcase(s, tc_map_cb_ok);

    /* Test additional secondary slices */
    TCase *tc_map_additional_secondary_slices = \
        tcase_create("IDMAP additional secondary slices");

    tcase_add_checked_fixture(tc_map_additional_secondary_slices,
                              ck_leak_check_setup,
                              ck_leak_check_teardown);
    tcase_add_checked_fixture(tc_map_additional_secondary_slices,
                              idmap_ctx_setup_additional_secondary_slices,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map_additional_secondary_slices,
                              idmap_add_domain_with_sec_slices_setup,
                              NULL);

    tcase_add_test(tc_map_additional_secondary_slices,
                   idmap_test_sid2uid_additional_secondary_slices);

    suite_add_tcase(s, tc_map_additional_secondary_slices);

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
