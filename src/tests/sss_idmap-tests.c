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
#include "tests/common.h"

#define IDMAP_RANGE_MIN 1234
#define IDMAP_RANGE_MAX 9876

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

    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    fail_unless(idmap_ctx != NULL, "sss_idmap_init returned NULL.");
}

void idmap_ctx_teardown(void)
{
    enum idmap_error_code err;

    err = sss_idmap_free(idmap_ctx);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}

void idmap_add_domain_setup(void)
{
    enum idmap_error_code err;
    struct sss_idmap_range range = {IDMAP_RANGE_MIN, IDMAP_RANGE_MAX};

    err = sss_idmap_add_domain(idmap_ctx, "test.dom", "S-1-5-21-1-2-3", &range);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_add_domain failed.");
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

    fail_if(is_domain_sid(NULL), "is_domain_sid() returned true for [NULL]");
    for (c = 0; invalid[c] != NULL; c++) {
        fail_if(is_domain_sid(invalid[c]),
                "is_domain_sid() returned true for [%s]", invalid[c]);
    }

    fail_unless(is_domain_sid("S-1-5-21-1-2-3"),
                "is_domain_sid() returned true for [S-1-5-21-1-2-3]");
}
END_TEST

START_TEST(idmap_test_init_malloc)
{
    enum idmap_error_code err;
    struct sss_idmap_ctx *ctx = NULL;

    err = sss_idmap_init(NULL, NULL, NULL, &ctx);

    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    fail_unless(ctx != NULL, "sss_idmap_init returned NULL.");

    err = sss_idmap_free(ctx);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}
END_TEST

START_TEST(idmap_test_init_talloc)
{
    enum idmap_error_code err;
    struct sss_idmap_ctx *ctx = NULL;

    err = sss_idmap_init(idmap_talloc, global_talloc_context, idmap_talloc_free,
                         &ctx);

    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_init failed.");
    fail_unless(ctx != NULL, "sss_idmap_init returned NULL.");

    err = sss_idmap_free(ctx);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_free failed.");
}
END_TEST

START_TEST(idmap_test_add_domain)
{
    idmap_add_domain_setup();
}
END_TEST

START_TEST(idmap_test_sid2uid)
{
    enum idmap_error_code err;
    uint32_t id;

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3333-1000", &id);
    fail_unless(err == IDMAP_NO_DOMAIN, "sss_idmap_sid_to_unix did not detect "
                                        "unknown domain");

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-10000", &id);
    fail_unless(err == IDMAP_NO_RANGE, "sss_idmap_sid_to_unix did not detect "
                                       "RID out of range");

    err = sss_idmap_sid_to_unix(idmap_ctx, "S-1-5-21-1-2-3-1000", &id);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_sid_to_unix failed.");
    fail_unless(id == (1000 + IDMAP_RANGE_MIN),
                "sss_idmap_sid_to_unix returned wrong id, "
                "got [%d], expected [%d].", id, 1000 + IDMAP_RANGE_MIN);
}
END_TEST

START_TEST(idmap_test_uid2sid)
{
    enum idmap_error_code err;
    char *sid;

    err = sss_idmap_unix_to_sid(idmap_ctx, 10000, &sid);
    fail_unless(err == IDMAP_NO_DOMAIN, "sss_idmap_unix_to_sid did not detect "
                                        "id out of range");

    err = sss_idmap_unix_to_sid(idmap_ctx, 2234, &sid);
    fail_unless(err == IDMAP_SUCCESS, "sss_idmap_unix_to_sid failed.");
    fail_unless(strcmp(sid, "S-1-5-21-1-2-3-1000") == 0,
                "sss_idmap_unix_to_sid returned wrong SID, "
                "expected [%s], got [%s].", "S-1-5-21-1-2-3-1000", sid);

    talloc_free(sid);
}
END_TEST

Suite *idmap_test_suite (void)
{
    Suite *s = suite_create ("IDMAP");

    TCase *tc_init = tcase_create("IDMAP init tests");
    tcase_add_checked_fixture(tc_init,
                              leak_check_setup,
                              leak_check_teardown);

    tcase_add_test(tc_init, idmap_test_init_malloc);
    tcase_add_test(tc_init, idmap_test_init_talloc);
    tcase_add_test(tc_init, idmap_test_is_domain_sid);

    suite_add_tcase(s, tc_init);

    TCase *tc_dom = tcase_create("IDMAP domain tests");
    tcase_add_checked_fixture(tc_dom,
                              leak_check_setup,
                              leak_check_teardown);
    tcase_add_checked_fixture(tc_dom,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);

    tcase_add_test(tc_dom, idmap_test_add_domain);

    suite_add_tcase(s, tc_dom);

    TCase *tc_map = tcase_create("IDMAP mapping tests");
    tcase_add_checked_fixture(tc_map,
                              leak_check_setup,
                              leak_check_teardown);
    tcase_add_checked_fixture(tc_map,
                              idmap_ctx_setup,
                              idmap_ctx_teardown);
    tcase_add_checked_fixture(tc_map,
                              idmap_add_domain_setup,
                              NULL);

    tcase_add_test(tc_map, idmap_test_sid2uid);
    tcase_add_test(tc_map, idmap_test_uid2sid);

    suite_add_tcase(s, tc_map);
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
