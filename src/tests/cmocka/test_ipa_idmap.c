/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Unit tests for id-mapping in the IPA provider

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
#include "providers/ipa/ipa_common.h"
#include "providers/ldap/sdap_idmap.h"

#define RANGE_NAME discard_const("range1")
#define DOMAIN_SID discard_const("S-1-5-21-2-3-4")
#define DOMAIN_NAME discard_const("dom.test")
#define BASE_RID 111
#define SECONDARY_BASE_RID 11223344
#define BASE_ID 123456
#define RANGE_SIZE 222222
#define RANGE_MAX (BASE_ID + RANGE_SIZE - 1)

void test_get_idmap_data_from_range(void **state)
{
    char *dom_name;
    char *sid;
    uint32_t rid;
    struct sss_idmap_range range;
    bool external_mapping;
    size_t c;
    errno_t ret;

    struct test_data {
        struct range_info r;
        errno_t exp_ret;
        char *exp_dom_name;
        char *exp_sid;
        uint32_t exp_rid;
        struct sss_idmap_range exp_range;
        bool exp_external_mapping;
    } d[] = {
        /* working IPA_RANGE_LOCAL range */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, SECONDARY_BASE_RID,
          NULL, discard_const(IPA_RANGE_LOCAL), MPG_DEFAULT},
         EOK, DOMAIN_NAME, NULL, 0, {BASE_ID, RANGE_MAX}, true},
        /* working old-style IPA_RANGE_LOCAL range without range type */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, SECONDARY_BASE_RID,
          NULL, NULL, MPG_DEFAULT},
         EOK, DOMAIN_NAME, NULL, 0, {BASE_ID, RANGE_MAX}, true},
        /* old-style IPA_RANGE_LOCAL without SID and secondary base rid */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, 0, NULL, NULL,
          MPG_DEFAULT},
         EINVAL, NULL, NULL, 0, {0, 0}, false},
        /* old-style range with SID and secondary base rid */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, SECONDARY_BASE_RID,
          DOMAIN_SID, NULL, MPG_DEFAULT},
         EINVAL, NULL, NULL, 0, {0, 0}, false},
        /* working IPA_RANGE_AD_TRUST range */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, 0, DOMAIN_SID,
          discard_const(IPA_RANGE_AD_TRUST), MPG_DEFAULT},
         EOK, DOMAIN_SID, DOMAIN_SID, BASE_RID, {BASE_ID, RANGE_MAX}, false},
        /* working old-style IPA_RANGE_AD_TRUST range without range type */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, 0, DOMAIN_SID, NULL,
          MPG_DEFAULT},
         EOK, DOMAIN_SID, DOMAIN_SID, BASE_RID, {BASE_ID, RANGE_MAX}, false},
        /* working IPA_RANGE_AD_TRUST_POSIX range */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, 0, DOMAIN_SID,
          discard_const(IPA_RANGE_AD_TRUST_POSIX), MPG_DEFAULT},
         EOK, DOMAIN_SID, DOMAIN_SID, 0, {BASE_ID, RANGE_MAX}, true},
        /* IPA_RANGE_AD_TRUST range  with unsupported type */
        {{RANGE_NAME, BASE_ID, RANGE_SIZE, BASE_RID, 0, DOMAIN_SID,
          discard_const("unsupported-range"), MPG_DEFAULT},
         ERR_UNSUPPORTED_RANGE_TYPE, NULL, NULL, 0, {0, 0}, false},
        {{0}, 0, NULL, NULL, 0, {0, 0}, false}
    };

    for (c = 0; d[c].exp_dom_name != NULL || d[c].exp_ret != 0; c++) {
        ret = get_idmap_data_from_range(&d[c].r, DOMAIN_NAME, &dom_name, &sid,
                                        &rid, &range, &external_mapping);
        assert_int_equal(ret, d[c].exp_ret);
        if (ret == 0) {
            assert_string_equal(dom_name, d[c].exp_dom_name);
            if (d[c].exp_sid == NULL) {
                assert_null(sid);
            } else {
                assert_string_equal(sid, d[c].exp_sid);
            }
            assert_int_equal(rid, d[c].exp_rid);
            assert_int_equal(range.min, d[c].exp_range.min);
            assert_int_equal(range.max, d[c].exp_range.max);
            assert_true(external_mapping == d[c].exp_external_mapping);
        }
    }
}

errno_t __wrap_sysdb_get_ranges(TALLOC_CTX *mem_ctx, struct sysdb_ctx *sysdb,
                                size_t *range_count,
                                struct range_info ***range_list)
{

    *range_count = sss_mock_type(size_t);
    *range_list = talloc_steal(mem_ctx,
                               sss_mock_ptr_type(struct range_info **));
    return EOK;
}

struct test_ctx {
    struct sdap_idmap_ctx *idmap_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
};

static struct range_info **get_range_list(TALLOC_CTX *mem_ctx)
{
    struct range_info **range_list;

    range_list = talloc_array(mem_ctx, struct range_info *, 2);
    assert_non_null(range_list);

    range_list[0] = talloc_zero(range_list, struct range_info);
    assert_non_null(range_list[0]);

    range_list[0]->name = talloc_strdup(range_list[0], RANGE_NAME);
    assert_non_null( range_list[0]->name);
    range_list[0]->base_id = BASE_ID;
    range_list[0]->id_range_size = RANGE_SIZE;
    range_list[0]->base_rid = BASE_RID;
    range_list[0]->secondary_base_rid = 0;
    range_list[0]->trusted_dom_sid = talloc_strdup(range_list[0], DOMAIN_SID);
    assert_non_null(range_list[0]->trusted_dom_sid);
    range_list[0]->range_type = talloc_strdup(range_list[0],
                                              IPA_RANGE_AD_TRUST);
    assert_non_null(range_list[0]->range_type);

    return range_list;
}

static int setup_idmap_ctx(void **state)
{
    int ret;
    struct test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->sdap_id_ctx = talloc_zero(test_ctx,
                                        struct sdap_id_ctx);
    assert_non_null(test_ctx->sdap_id_ctx);

    test_ctx->sdap_id_ctx->be = talloc_zero(test_ctx->sdap_id_ctx,
                                            struct be_ctx);
    assert_non_null(test_ctx->sdap_id_ctx->be);

    test_ctx->sdap_id_ctx->be->domain = talloc_zero(test_ctx->sdap_id_ctx->be,
                                                    struct sss_domain_info);
    assert_non_null(test_ctx->sdap_id_ctx->be->domain);

    test_ctx->sdap_id_ctx->be->domain->name =
                  talloc_strdup(test_ctx->sdap_id_ctx->be->domain, DOMAIN_NAME);
    assert_non_null(test_ctx->sdap_id_ctx->be->domain->name);

    will_return(__wrap_sysdb_get_ranges, 1);
    will_return(__wrap_sysdb_get_ranges, get_range_list(global_talloc_context));

    ret = ipa_idmap_init(test_ctx, test_ctx->sdap_id_ctx,
                         &test_ctx->idmap_ctx);
    assert_int_equal(ret, EOK);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int teardown_idmap_ctx(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);

    assert_non_null(test_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

void test_ipa_idmap_get_ranges_from_sysdb(void **state)
{
    int ret;
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);

    will_return(__wrap_sysdb_get_ranges, 1);
    will_return(__wrap_sysdb_get_ranges, get_range_list(test_ctx->idmap_ctx));
    ret = ipa_idmap_get_ranges_from_sysdb(test_ctx->idmap_ctx,
                                          DOMAIN_NAME, DOMAIN_SID, true);
    assert_int_equal(ret, EOK);

    will_return(__wrap_sysdb_get_ranges, 1);
    will_return(__wrap_sysdb_get_ranges, get_range_list(global_talloc_context));
    ret = ipa_idmap_get_ranges_from_sysdb(test_ctx->idmap_ctx,
                                          DOMAIN_NAME, DOMAIN_SID, false);
    assert_int_equal(ret, EIO);
}

struct sysdb_attrs *create_range_attrs(TALLOC_CTX *mem_ctx,
                                       struct range_info *r)
{
    int ret;
    struct sysdb_attrs *a = NULL;

    a = sysdb_new_attrs(mem_ctx);
    assert_non_null(a);

    ret = sysdb_attrs_add_string(a, IPA_CN, r->name);

    if (ret == 0) {
        ret = sysdb_attrs_add_string(a, IPA_TRUSTED_DOMAIN_SID,
                                     r->trusted_dom_sid);
    }

    if (ret == 0) {
        ret = sysdb_attrs_add_uint32(a, IPA_BASE_ID, r->base_id);
    }

    if (ret == 0) {
        ret = sysdb_attrs_add_uint32(a, IPA_ID_RANGE_SIZE, r->id_range_size);
    }

    if (ret == 0) {
        ret = sysdb_attrs_add_uint32(a, IPA_BASE_RID, r->base_rid);
    }

    if (ret == 0) {
        ret = sysdb_attrs_add_uint32(a, IPA_SECONDARY_BASE_RID,
                                     r->secondary_base_rid);
    }

    if (ret == 0) {
        ret = sysdb_attrs_add_string(a, IPA_RANGE_TYPE, r->range_type);
    }

    if (ret != 0) {
        talloc_zfree(a);
    }

    return a;

}


void test_ipa_ranges_parse_results(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    assert_non_null(test_ctx);
    int ret;
    size_t count = 5;
    size_t c;
    size_t d;
    struct sysdb_attrs *reply[5];
    struct range_info **range_list;
    struct range_info r[5] = {
        { discard_const("range1"), 1000, 500, 0, 1000, discard_const("S-1-2-1"), discard_const(IPA_RANGE_AD_TRUST), MPG_DEFAULT },
        { discard_const("range2"), 2000, 500, 0, 2000, discard_const("S-1-2-2"), discard_const(IPA_RANGE_AD_TRUST), MPG_DEFAULT },
        { discard_const("range3"), 3000, 500, 0, 3000, discard_const("S-1-2-3"), discard_const("unsupported-type"), MPG_DEFAULT },
        { discard_const("range4"), 4000, 500, 0, 4000, discard_const("S-1-2-4"), discard_const(IPA_RANGE_AD_TRUST), MPG_DEFAULT },
        { discard_const("range5"), 5000, 500, 0, 5000, discard_const("S-1-2-5"), discard_const(IPA_RANGE_AD_TRUST), MPG_DEFAULT }
    };

    for (c = 0; c < count; c++) {
        reply[c] = create_range_attrs(test_ctx, &r[c]);
        assert_non_null(reply[c]);
    }

    ret = ipa_ranges_parse_results(test_ctx, discard_const("mydom"),
                                   count, reply, &range_list);
    for (c = 0; c < count; c++) {
        talloc_free(reply[c]);
    }
    assert_int_equal(ret, EOK);
    d = 0;
    for (c = 0; c < count; c++) {
        if (strcmp(r[c].range_type, "unsupported-type") == 0) {
            continue;
        }
        assert_string_equal(r[c].name, range_list[d]->name);
        assert_string_equal(r[c].trusted_dom_sid,
                            range_list[d]->trusted_dom_sid);
        assert_string_equal(r[c].range_type, range_list[d]->range_type);
        assert_int_equal(r[c].base_id, range_list[d]->base_id);
        assert_int_equal(r[c].id_range_size, range_list[d]->id_range_size);
        assert_int_equal(r[c].base_rid, range_list[d]->base_rid);
        assert_int_equal(r[c].secondary_base_rid,
                         range_list[d]->secondary_base_rid);
        d++;
    }

    talloc_free(range_list);
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
        cmocka_unit_test(test_get_idmap_data_from_range),
        cmocka_unit_test_setup_teardown(test_ipa_idmap_get_ranges_from_sysdb,
                                        setup_idmap_ctx, teardown_idmap_ctx),
        cmocka_unit_test_setup_teardown(test_ipa_ranges_parse_results,
                                        setup_idmap_ctx, teardown_idmap_ctx),
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
