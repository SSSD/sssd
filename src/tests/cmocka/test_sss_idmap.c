/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Unit tests for libsss_idmap

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

#include "tests/cmocka/common_mock.h"

#include "lib/idmap/sss_idmap.h"

#define TEST_RANGE_MIN 200000
#define TEST_RANGE_MAX 399999
#define TEST_DOM_NAME "test.dom"
#define TEST_DOM_SID "S-1-5-21-123-456-789"
#define TEST_FIRST_RID 0
#define TEST_EXT_MAPPING true

#define TEST_2_RANGE_MIN 600000
#define TEST_2_RANGE_MAX 799999
#define TEST_2_DOM_NAME "test2.dom"
#define TEST_2_DOM_SID "S-1-5-21-987-654-321"
#define TEST_2_FIRST_RID 1000000
#define TEST_2_EXT_MAPPING true

#define TEST_OFFSET 1000000
#define TEST_OFFSET_STR "1000000"

const int TEST_2922_MIN_ID = 1842600000;
const int TEST_2922_MAX_ID = 1842799999;

struct test_ctx {
    TALLOC_CTX *mem_idmap;
    struct sss_idmap_ctx *idmap_ctx;
};

static void *idmap_talloc(size_t size, void *pvt)
{
    return talloc_size(pvt, size);
}

static void idmap_free(void *ptr, void *pvt)
{
    talloc_free(ptr);
}

static int test_sss_idmap_setup(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    check_leaks_push(test_ctx);

    test_ctx->mem_idmap = talloc_new(test_ctx);
    assert_non_null(test_ctx->mem_idmap);

    err = sss_idmap_init(idmap_talloc, test_ctx->mem_idmap, idmap_free,
                         &test_ctx->idmap_ctx);
    assert_int_equal(err, IDMAP_SUCCESS);

    *state = test_ctx;
    return 0;
}

static int setup_ranges(struct test_ctx *test_ctx, bool external_mapping,
                        bool second_domain, bool sec_slices)
{
    struct sss_idmap_range range;
    enum idmap_error_code err;
    const char *name;
    const char *sid;

    assert_non_null(test_ctx);

    if (second_domain) {
        range.min = TEST_2_RANGE_MIN;
        range.max = TEST_2_RANGE_MAX;
        name = TEST_2_DOM_NAME;
        sid = TEST_2_DOM_SID;
    } else {
        range.min = TEST_RANGE_MIN;
        range.max = TEST_RANGE_MAX;
        name = TEST_DOM_NAME;
        sid = TEST_DOM_SID;
    }

    if (sec_slices) {
        err = sss_idmap_add_auto_domain_ex(test_ctx->idmap_ctx, name, sid,
                                           &range, NULL, 0, external_mapping,
                                           NULL, NULL);
    } else {
        err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, name, sid, &range,
                                      NULL, 0, external_mapping);
    }
    assert_int_equal(err, IDMAP_SUCCESS);

    range.min += TEST_OFFSET;
    range.max += TEST_OFFSET;

    if (sec_slices) {
        err = sss_idmap_add_auto_domain_ex(test_ctx->idmap_ctx, name, sid,
                                           &range, NULL, TEST_OFFSET,
                                           external_mapping, NULL, NULL);
    } else {
        err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, name, sid, &range,
                                      NULL, TEST_OFFSET, external_mapping);
    }
    assert_int_equal(err, IDMAP_SUCCESS);
    return 0;
}

static int setup_ranges_2922(struct test_ctx *test_ctx)
{
    const int TEST_2922_DFL_SLIDE = 9212;
    struct sss_idmap_range range;
    enum idmap_error_code err;
    const char *name;
    const char *sid;
    /* Pick a new slice. */
    id_t slice_num = -1;

    assert_non_null(test_ctx);

    name = TEST_DOM_NAME;
    sid = TEST_DOM_SID;

    err = sss_idmap_calculate_range(test_ctx->idmap_ctx, sid, &slice_num,
                                    &range);
    assert_int_equal(err, IDMAP_SUCCESS);
    /* Range computation should be deterministic. Lets validate that.  */
    assert_int_equal(range.min, TEST_2922_MIN_ID);
    assert_int_equal(range.max, TEST_2922_MAX_ID);
    assert_int_equal(slice_num, TEST_2922_DFL_SLIDE);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, name, sid, &range,
                                  NULL, 0, false /* No external mapping */);
    assert_int_equal(err, IDMAP_SUCCESS);

    return 0;
}

static int test_sss_idmap_setup_with_domains(void **state)
{
    struct test_ctx *test_ctx;

    test_sss_idmap_setup(state);

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    setup_ranges(test_ctx, false, false, false);
    return 0;
}

static int test_sss_idmap_setup_with_domains_2922(void **state)
{
    struct test_ctx *test_ctx;

    test_sss_idmap_setup(state);

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    setup_ranges_2922(test_ctx);
    return 0;
}

static int test_sss_idmap_setup_with_domains_sec_slices(void **state)
{
    struct test_ctx *test_ctx;

    test_sss_idmap_setup(state);

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    setup_ranges(test_ctx, false, false, true);
    return 0;
}

static int test_sss_idmap_setup_with_external_mappings(void **state)
{
    struct test_ctx *test_ctx;

    test_sss_idmap_setup(state);

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    setup_ranges(test_ctx, true, false, false);
    return 0;
}

static int test_sss_idmap_setup_with_both(void **state)
{
    struct test_ctx *test_ctx;

    test_sss_idmap_setup(state);

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    setup_ranges(test_ctx, false, false, false);
    setup_ranges(test_ctx, true, true, false);
    return 0;
}

static int test_sss_idmap_teardown(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    talloc_free(test_ctx->idmap_ctx);
    talloc_free(test_ctx->mem_idmap);
    assert_true(check_leaks_pop(test_ctx) == true);
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_add_domain(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    range.min = TEST_RANGE_MIN;
    range.max = TEST_RANGE_MAX;

    err = sss_idmap_add_domain(test_ctx->idmap_ctx, TEST_DOM_NAME, TEST_DOM_SID,
                               &range);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_add_domain(test_ctx->idmap_ctx, TEST_DOM_NAME, TEST_DOM_SID,
                               &range);
    assert_int_equal(err, IDMAP_COLLISION);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID, &range, NULL, 0, false);
    assert_int_equal(err, IDMAP_COLLISION);

    range.min = TEST_RANGE_MIN + TEST_OFFSET;
    range.max = TEST_RANGE_MAX + TEST_OFFSET;
    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID, &range, NULL, 0, false);
    assert_int_equal(err, IDMAP_COLLISION);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME"X",
                                  TEST_DOM_SID, &range, NULL, TEST_OFFSET,
                                  false);
    assert_int_equal(err, IDMAP_COLLISION);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID"1", &range, NULL, TEST_OFFSET,
                                  false);
    assert_int_equal(err, IDMAP_COLLISION);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID, &range, NULL, TEST_OFFSET,
                                  true);
    assert_int_equal(err, IDMAP_COLLISION);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID, &range, NULL, TEST_OFFSET,
                                  false);
    assert_int_equal(err, IDMAP_SUCCESS);

    range.min = TEST_RANGE_MIN + 2 * TEST_OFFSET;
    range.max = TEST_RANGE_MAX + 2 * TEST_OFFSET;
    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME"-nosid",
                                  NULL, &range, NULL, TEST_OFFSET,
                                  false);
    assert_int_equal(err, IDMAP_SID_INVALID);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME"-nosid",
                                  NULL, &range, NULL, TEST_OFFSET,
                                  true);
    assert_int_equal(err, IDMAP_SUCCESS);
}

void test_map_id(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    uint32_t id;
    char *sid = NULL;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"1-1", &id);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                &id);
    assert_int_equal(err, IDMAP_NO_RANGE);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_OFFSET - 1, &sid);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-0", &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_RANGE_MIN);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, id, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_DOM_SID"-0");
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx,
                                TEST_DOM_SID"-"TEST_OFFSET_STR, &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_RANGE_MIN+TEST_OFFSET);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, id, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_DOM_SID"-"TEST_OFFSET_STR);
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);
}

/* https://fedorahosted.org/sssd/ticket/2922 */
/* ID mapping - bug in computing max id for slice range */
void test_map_id_2922(void **state)
{
    const char* TEST_2922_FIRST_SID = TEST_DOM_SID"-0";
    /* Last SID = first SID + (default) rangesize -1 */
    const char* TEST_2922_LAST_SID = TEST_DOM_SID"-199999";
    /* Last SID = first SID + rangesize */
    const char* TEST_2922_LAST_SID_PLUS_ONE = TEST_DOM_SID"-200000";
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    uint32_t id;
    char *sid = NULL;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    /* Min UNIX ID to SID */
    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_2922_MIN_ID, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_2922_FIRST_SID);
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);

    /* First SID to UNIX ID */
    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_2922_FIRST_SID, &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_2922_MIN_ID);

    /* Max UNIX ID to SID */
    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_2922_MAX_ID, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_2922_LAST_SID);
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);

    /* Last SID to UNIX ID */
    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_2922_LAST_SID, &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_2922_MAX_ID);

    /* Max UNIX ID + 1 to SID */
    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_2922_MAX_ID + 1,
                                &sid);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    /* Last SID + 1 to UNIX ID */
    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx,
                                TEST_2922_LAST_SID_PLUS_ONE, &id);
    /* Auto adding new ranges is disable in this test.  */
    assert_int_equal(err, IDMAP_NO_RANGE);
}

void test_map_id_sec_slices(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    uint32_t id;
    char *sid = NULL;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"1-1", &id);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-4000000",
                                &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, 575600000);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_OFFSET - 1, &sid);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-0", &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_RANGE_MIN);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, id, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_DOM_SID"-0");
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx,
                                TEST_DOM_SID"-"TEST_OFFSET_STR, &id);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(id, TEST_RANGE_MIN+TEST_OFFSET);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, id, &sid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(sid, TEST_DOM_SID"-"TEST_OFFSET_STR);
    sss_idmap_free_sid(test_ctx->idmap_ctx, sid);
}

void test_map_id_external(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    uint32_t id;
    char *sid = NULL;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"1-1", &id);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                &id);
    assert_int_equal(err, IDMAP_EXTERNAL);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_OFFSET - 1, &sid);
    assert_int_equal(err, IDMAP_NO_DOMAIN);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-0", &id);
    assert_int_equal(err, IDMAP_EXTERNAL);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx, TEST_RANGE_MIN, &sid);
    assert_int_equal(err, IDMAP_EXTERNAL);

    err = sss_idmap_sid_to_unix(test_ctx->idmap_ctx,
                                TEST_DOM_SID"-"TEST_OFFSET_STR, &id);
    assert_int_equal(err, IDMAP_EXTERNAL);

    err = sss_idmap_unix_to_sid(test_ctx->idmap_ctx,
                                TEST_RANGE_MIN + TEST_OFFSET, &sid);
    assert_int_equal(err, IDMAP_EXTERNAL);
}

void test_check_sid_id(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_check_sid_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                   TEST_RANGE_MIN-1);
    assert_int_equal(err, IDMAP_NO_RANGE);

    err = sss_idmap_check_sid_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                   TEST_RANGE_MIN);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_check_sid_unix(test_ctx->idmap_ctx, TEST_DOM_SID"1-400000",
                                   TEST_RANGE_MIN);
    assert_int_equal(err, IDMAP_SID_UNKNOWN);

    err = sss_idmap_check_sid_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                   TEST_RANGE_MAX + TEST_OFFSET);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_check_sid_unix(test_ctx->idmap_ctx, TEST_DOM_SID"-400000",
                                   TEST_RANGE_MAX + TEST_OFFSET + 1);
    assert_int_equal(err, IDMAP_NO_RANGE);
}

void test_has_algorithmic(void **state)
{
    struct test_ctx *test_ctx;
    bool use_id_mapping;
    enum idmap_error_code err;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_domain_has_algorithmic_mapping(NULL, NULL, &use_id_mapping);
    assert_int_equal(err, IDMAP_SID_INVALID);

    err = sss_idmap_domain_has_algorithmic_mapping(NULL, TEST_DOM_SID,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_domain_has_algorithmic_mapping(test_ctx->idmap_ctx, NULL,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SID_INVALID);

    err = sss_idmap_domain_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_DOM_SID"1",
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SID_UNKNOWN);

    err = sss_idmap_domain_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_DOM_SID,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_true(use_id_mapping);

    err = sss_idmap_domain_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_2_DOM_SID,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_false(use_id_mapping);
}

void test_has_algorithmic_by_name(void **state)
{
    struct test_ctx *test_ctx;
    bool use_id_mapping;
    enum idmap_error_code err;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(NULL, NULL, &use_id_mapping);
    assert_int_equal(err, IDMAP_ERROR);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(NULL, TEST_DOM_SID,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_CONTEXT_INVALID);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(test_ctx->idmap_ctx, NULL,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_ERROR);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_DOM_NAME"1",
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_NAME_UNKNOWN);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_DOM_NAME,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_true(use_id_mapping);

    err = sss_idmap_domain_by_name_has_algorithmic_mapping(test_ctx->idmap_ctx,
                                                   TEST_2_DOM_NAME,
                                                   &use_id_mapping);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_false(use_id_mapping);
}

void test_sss_idmap_check_collision_ex(void **state)
{
    enum idmap_error_code err;
    struct sss_idmap_range r1 = {TEST_RANGE_MIN, TEST_RANGE_MAX};
    struct sss_idmap_range r2 = {TEST_2_RANGE_MIN, TEST_2_RANGE_MAX};

    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       TEST_EXT_MAPPING,
                                       TEST_2_DOM_NAME, TEST_2_DOM_SID, &r2,
                                       TEST_2_FIRST_RID, NULL,
                                       TEST_2_EXT_MAPPING);
    assert_int_equal(err, IDMAP_SUCCESS);

    /* Same name, different SID */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       TEST_EXT_MAPPING,
                                       TEST_DOM_NAME, TEST_2_DOM_SID, &r2,
                                       TEST_2_FIRST_RID, NULL,
                                       TEST_2_EXT_MAPPING);
    assert_int_equal(err, IDMAP_COLLISION);

    /* Same SID, different name */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       TEST_EXT_MAPPING,
                                       TEST_2_DOM_NAME, TEST_DOM_SID, &r2,
                                       TEST_2_FIRST_RID, NULL,
                                       TEST_2_EXT_MAPPING);
    assert_int_equal(err, IDMAP_COLLISION);

    /* Same SID and name, no overlaps */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       TEST_EXT_MAPPING,
                                       TEST_DOM_NAME, TEST_DOM_SID, &r2,
                                       TEST_2_FIRST_RID, NULL,
                                       TEST_2_EXT_MAPPING);
    assert_int_equal(err, IDMAP_SUCCESS);

    /* Same SID and name, different mappings */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       TEST_EXT_MAPPING,
                                       TEST_DOM_NAME, TEST_DOM_SID, &r2,
                                       TEST_2_FIRST_RID, NULL,
                                       !TEST_EXT_MAPPING);
    assert_int_equal(err, IDMAP_COLLISION);

    /* Same SID and name, Overlapping RID range */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       false,
                                       TEST_DOM_NAME, TEST_DOM_SID, &r2,
                                       TEST_FIRST_RID, NULL,
                                       false);
    assert_int_equal(err, IDMAP_COLLISION);

    /* Different SID and name, Overlapping RID range */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       false,
                                       TEST_2_DOM_NAME, TEST_2_DOM_SID, &r2,
                                       TEST_FIRST_RID, NULL,
                                       false);
    assert_int_equal(err, IDMAP_SUCCESS);


    /* Overlapping ranges with no external mapping */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       false,
                                       TEST_2_DOM_NAME, TEST_2_DOM_SID, &r1,
                                       TEST_2_FIRST_RID, NULL,
                                       false);
    assert_int_equal(err, IDMAP_COLLISION);

    /* Overlapping ranges with external mapping */
    err = sss_idmap_check_collision_ex(TEST_DOM_NAME, TEST_DOM_SID, &r1,
                                       TEST_FIRST_RID, NULL,
                                       true,
                                       TEST_2_DOM_NAME, TEST_2_DOM_SID, &r1,
                                       TEST_2_FIRST_RID, NULL,
                                       true);
    assert_int_equal(err, IDMAP_SUCCESS);
}

void test_sss_idmap_error_string(void **state)
{
    size_t c;

    for (c = IDMAP_SUCCESS; c < IDMAP_ERR_LAST; c++) {
        assert_string_not_equal(idmap_error_string(c),
                                idmap_error_string(IDMAP_ERR_LAST));
    }
}

void test_sss_idmap_calculate_range_slice_collision(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    id_t slice_num = 123;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    err = sss_idmap_calculate_range(test_ctx->idmap_ctx, NULL, &slice_num,
                                    &range);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_add_domain_ex(test_ctx->idmap_ctx, TEST_DOM_NAME,
                                  TEST_DOM_SID, &range, NULL, 0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_calculate_range(test_ctx->idmap_ctx, NULL, &slice_num,
                                    &range);
    assert_int_equal(err, IDMAP_COLLISION);

    slice_num++;
    err = sss_idmap_calculate_range(test_ctx->idmap_ctx, NULL, &slice_num,
                                    &range);
    assert_int_equal(err, IDMAP_SUCCESS);
}

void test_sss_idmap_add_gen_domain_ex(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_COLLISION);

    range.min = 2000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP2.TEST",
                                      "https://idp2.test", &range,
                                      "https://idp2.test", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_SUCCESS);
}

void test_sss_idmap_gen_to_unix(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uid_t uid;

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test/range", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "username", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 1130028);

    range.min = 2000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP2.TEST",
                                      "https://idp2.test", &range,
                                      "https://idp2.test/range",
                                      sss_idmap_offset_identity, NULL, NULL, 0,
                                      false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp2.test",
                                "username", &uid);
    assert_int_equal(err, IDMAP_ERROR);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp2.test",
                                "12345", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 2012345);
}

void test_sss_idmap_gen_to_unix_normalization(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uid_t uid;
    int expected_id = 1080838;

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    /* By default for the default murmurhash offset function the normalization
     * of UTF8 strings is enable and the Angstrom Sign and the Latin Capital
     * Letter A with Ring Above should be treated equally and strings
     * containing them should lead to the same ID value. */

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test/range", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xC3\x85ngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xE2\x84\xABngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);
}

void test_sss_idmap_gen_to_unix_no_normalization(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uid_t uid;
    struct sss_idmap_offset_murmurhash3_data my_offset_murmurhash3_data =
                                                          { .seed = 0xdeadbeef,
                                                            .normalize = false,
                                                            .casefold = false };


    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    /* Without normalization
     * of UTF8 strings Angstrom Sign and the Latin Capital Letter A with Ring
     * Above are represented differently and should lead to different ID
     * values because the murmurhash results should differ. */

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test/range",
                                      sss_idmap_offset_murmurhash3, NULL,
                                      &my_offset_murmurhash3_data, 0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xC3\x85ngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 1080838);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xE2\x84\xABngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 1005015);
}

void test_sss_idmap_gen_to_unix_casefold(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uid_t uid;
    int expected_id = 1112532;
    struct sss_idmap_offset_murmurhash3_data my_offset_murmurhash3_data =
                                                          { .seed = 0xdeadbeef,
                                                            .normalize = false,
                                                            .casefold = true };


    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    /* By default for the default murmurhash offset function the normalization
     * of UTF8 strings is enable and the Angstrom Sign and the Latin Capital
     * Letter A with Ring Above should be treated equally and strings
     * containing them should lead to the same ID value. */

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test/range",
                                      sss_idmap_offset_murmurhash3, NULL,
                                      &my_offset_murmurhash3_data, 0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xC3\x85ngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xE2\x84\xABngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xC3\xA5ngstr\xC3\xB6m", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "\xC3\x85NGSTR\xC3\x96M", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, expected_id);
}

void test_sss_idmap_unix_to_gen(void **state)
{
    struct test_ctx *test_ctx;
    enum idmap_error_code err;
    struct sss_idmap_range range;
    uid_t uid;
    char *out;

    test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    range.min = 1000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP.TEST",
                                      "https://idp.test", &range,
                                      "https://idp.test/range", NULL, NULL, NULL,
                                      0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp.test",
                                "username", &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 1130028);

    err = sss_idmap_unix_to_gen(test_ctx->idmap_ctx, uid, &out);
    assert_int_equal(err, IDMAP_NO_REVERSE);

    range.min = 2000000;
    range.max = range.min + 199999;

    err = sss_idmap_add_gen_domain_ex(test_ctx->idmap_ctx, "IDP2.TEST",
                                      "https://idp2.test", &range,
                                      "https://idp2.test/range",
                                      sss_idmap_offset_identity,
                                      sss_idmap_rev_offset_identity,
                                      NULL, 0, false);
    assert_int_equal(err, IDMAP_SUCCESS);

    err = sss_idmap_unix_to_gen(test_ctx->idmap_ctx, 2012345, &out);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_string_equal(out, "12345");

    err = sss_idmap_gen_to_unix(test_ctx->idmap_ctx, "https://idp2.test",
                                out, &uid);
    assert_int_equal(err, IDMAP_SUCCESS);
    assert_int_equal(uid, 2012345);
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
        cmocka_unit_test_setup_teardown(test_add_domain,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_map_id,
                                        test_sss_idmap_setup_with_domains,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_map_id_2922,
                                        test_sss_idmap_setup_with_domains_2922,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_map_id_sec_slices,
                                        test_sss_idmap_setup_with_domains_sec_slices,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_map_id_external,
                                        test_sss_idmap_setup_with_external_mappings,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_check_sid_id,
                                        test_sss_idmap_setup_with_domains,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_check_sid_id,
                                        test_sss_idmap_setup_with_external_mappings,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_has_algorithmic,
                                        test_sss_idmap_setup_with_both,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_has_algorithmic_by_name,
                                        test_sss_idmap_setup_with_both,
                                        test_sss_idmap_teardown),
        cmocka_unit_test(test_sss_idmap_check_collision_ex),
        cmocka_unit_test(test_sss_idmap_error_string),
        cmocka_unit_test_setup_teardown(test_sss_idmap_calculate_range_slice_collision,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_add_gen_domain_ex,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_gen_to_unix,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_unix_to_gen,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_gen_to_unix_normalization,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_gen_to_unix_no_normalization,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
        cmocka_unit_test_setup_teardown(test_sss_idmap_gen_to_unix_casefold,
                                        test_sss_idmap_setup,
                                        test_sss_idmap_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
