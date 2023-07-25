/*
    Authors:
        Yassir Elley <yelley@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: GPO unit tests

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

/* In order to access opaque types */
#include "providers/ad/ad_gpo.c"

#include "tests/cmocka/common_mock.h"

struct ad_gpo_test_ctx {
    struct ldb_context *ldb_ctx;
};

static struct ad_gpo_test_ctx *test_ctx;

static int ad_gpo_test_setup(void **state)
{
    assert_true(leak_check_setup());
    test_ctx = talloc_zero(global_talloc_context,
                           struct ad_gpo_test_ctx);
    assert_non_null(test_ctx);

    test_ctx->ldb_ctx = ldb_init(test_ctx, NULL);
    assert_non_null(test_ctx->ldb_ctx);
    return 0;
}

static int ad_gpo_test_teardown(void **state)
{
    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

struct som_list_result {
    const int result;
    const int num_soms;
    const char **som_dns;
};

/*
 * Test parsing target DN into som components
 */
static void test_populate_som_list(const char *target_dn,
                                   struct som_list_result *expected)
{
    errno_t ret;
    int i;
    int num_soms;
    struct gp_som **som_list = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    ret = ad_gpo_populate_som_list(tmp_ctx,
                                   test_ctx->ldb_ctx,
                                   target_dn,
                                   &num_soms,
                                   &som_list);

    assert_int_equal(ret, expected->result);
    if (ret != EOK) {
        goto done;
    }

    assert_int_equal(num_soms, expected->num_soms);

    for (i=0; i<expected->num_soms; i++){
        bool equal = true;
        if (strncmp(som_list[i]->som_dn,
                    expected->som_dns[i],
                    strlen(expected->som_dns[i])) != 0) {
            equal = false;
        }

        assert_int_equal(equal, true);
    }

    if (som_list) {
        talloc_free(som_list);
    }

 done:
    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void test_populate_som_list_plain(void **state)
{
    const char *som_dns[] = {"OU=West OU,OU=Sales OU,DC=foo,DC=com",
                             "OU=Sales OU,DC=foo,DC=com",
                             "DC=foo,DC=com"};

    struct som_list_result expected = {
        .result = EOK,
        .num_soms = 3,
        .som_dns = som_dns
    };

    test_populate_som_list("CN=F21-Client,OU=West OU,OU=Sales OU,DC=foo,DC=com",
                           &expected);
}

void test_populate_som_list_malformed(void **state)
{
    struct som_list_result expected = {
        .result = EINVAL,
    };

    test_populate_som_list("malformed target dn", &expected);
}

struct gplink_list_result {
    const int result;
    const int num_gplinks;
    const char **gpo_dns;
    bool *enforced;
};

/*
 * Test parsing raw_gplink_value into gplink components
 */
static void test_populate_gplink_list(const char *input_gplink_value,
                                      bool allow_enforced_only,
                                      struct gplink_list_result *expected)
{
    errno_t ret;
    int i;
    struct gp_gplink **gplink_list = NULL;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    char *raw_gplink_value = talloc_strdup(tmp_ctx, input_gplink_value);

    ret = ad_gpo_populate_gplink_list(tmp_ctx,
                                      NULL,
                                      raw_gplink_value,
                                      &gplink_list,
                                      allow_enforced_only);

    talloc_free(raw_gplink_value);

    assert_int_equal(ret, expected->result);
    if (ret != EOK) {
        goto done;
    }

    for (i=0; i<expected->num_gplinks; i++){
        bool equal = true;
        if (strncmp(gplink_list[i]->gpo_dn,
                    expected->gpo_dns[i],
                    strlen(expected->gpo_dns[i])) != 0) {
            equal = false;
        }

        if (gplink_list[i]->enforced != expected->enforced[i])
            equal = false;

        assert_int_equal(equal, true);
    }

    if (gplink_list) {
        talloc_free(gplink_list);
    }

 done:
    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void test_populate_gplink_list_plain(void **state)
{
    const char *gpo_dns[] = {"OU=Sales,DC=FOO,DC=COM", "DC=FOO,DC=COM"};
    bool enforced[] = {false, true};

    struct gplink_list_result expected = {
        .result = EOK,
        .num_gplinks = 2,
        .gpo_dns = gpo_dns,
        .enforced = enforced
    };

    test_populate_gplink_list("[OU=Sales,DC=FOO,DC=COM;0][DC=FOO,DC=COM;2]",
                              false,
                              &expected);
}

void test_populate_gplink_list_with_ignored(void **state)
{
    const char *gpo_dns[] = {"OU=Sales,DC=FOO,DC=COM"};
    bool enforced[] = {false};

    struct gplink_list_result expected = {
        .result = EOK,
        .num_gplinks = 1,
        .gpo_dns = gpo_dns,
        .enforced = enforced
    };

    test_populate_gplink_list("[OU=Sales,DC=FOO,DC=COM;0][DC=ignored;1]",
                              false,
                              &expected);
}

void test_populate_gplink_list_with_allow_enforced(void **state)
{
    const char *gpo_dns[] = {"DC=FOO,DC=COM"};
    bool enforced[] = {true};

    struct gplink_list_result expected = {
        .result = EOK,
        .num_gplinks = 1,
        .gpo_dns = gpo_dns,
        .enforced = enforced
    };

    test_populate_gplink_list("[OU=Sales,DC=FOO,DC=COM;0][DC=FOO,DC=COM;2]",
                              true,
                              &expected);
}

void test_populate_gplink_list_malformed(void **state)
{
    struct gplink_list_result expected = {
        .result = EINVAL,
    };

    test_populate_gplink_list(NULL, false, &expected);
    test_populate_gplink_list("[malformed]", false, &expected);
    /* the GPLinkOptions value (after semicolon) must be between 0 and 3 */
    test_populate_gplink_list("[gpo_dn; 4]", false, &expected);
}

/*
 * Test SID-matching logic
 */
static void test_ad_gpo_ace_includes_client_sid(const char *user_sid,
                                                const char *host_sid,
                                                const char **group_sids,
                                                int group_size,
                                                struct dom_sid ace_dom_sid,
                                                bool expected)
{
    errno_t ret;
    enum idmap_error_code err;
    struct sss_idmap_ctx *idmap_ctx;
    bool includes_client_sid;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(global_talloc_context);
    assert_non_null(tmp_ctx);
    check_leaks_push(tmp_ctx);

    err = sss_idmap_init(sss_idmap_talloc, tmp_ctx, sss_idmap_talloc_free,
                         &idmap_ctx);
    assert_int_equal(err, IDMAP_SUCCESS);

    ret = ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids,
                                         group_size, ace_dom_sid, idmap_ctx,
                                         &includes_client_sid);
    talloc_free(idmap_ctx);

    assert_int_equal(ret, EOK);

    assert_int_equal(includes_client_sid, expected);

    assert_true(check_leaks_pop(tmp_ctx) == true);
    talloc_free(tmp_ctx);
}

void test_ad_gpo_ace_includes_client_sid_true(void **state)
{
    /* ace_dom_sid represents "S-1-5-21-2-3-4" */
    struct dom_sid ace_dom_sid = {1, 4, {0, 0, 0, 0, 0, 5}, {21, 2, 3, 4}};

    const char *user_sid = "S-1-5-21-1175337206-4250576914-2321192831-1103";
    const char *host_sid = "S-1-5-21-1898687337-2196588786-2775055786-2102";

    int group_size = 2;
    const char *group_sids[] = {"S-1-5-21-2-3-4",
                                "S-1-5-21-2-3-5"};

    test_ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids,
                                        group_size, ace_dom_sid, true);
}

void test_ad_gpo_ace_includes_client_sid_false(void **state)
{
    /* ace_dom_sid represents "S-1-5-21-2-3-4" */
    struct dom_sid ace_dom_sid = {1, 4, {0, 0, 0, 0, 0, 5}, {21, 2, 3, 4}};

    const char *user_sid = "S-1-5-21-1175337206-4250576914-2321192831-1103";
    const char *host_sid = "S-1-5-21-1898687337-2196588786-2775055786-2102";

    int group_size = 2;
    const char *group_sids[] = {"S-1-5-21-2-3-5",
                                "S-1-5-21-2-3-6"};

    test_ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids,
                                        group_size, ace_dom_sid, false);
}

void test_ad_gpo_ace_includes_host_sid_true(void **state)
{
    /* ace_dom_sid represents "S-1-5-21-1898687337-2196588786-2775055786-2102" */
    struct dom_sid ace_dom_sid = {1, 5, {0, 0, 0, 0, 0, 5}, {21, 1898687337, 2196588786, 2775055786, 2102}};

    const char *user_sid = "S-1-5-21-1175337206-4250576914-2321192831-1103";
    const char *host_sid = "S-1-5-21-1898687337-2196588786-2775055786-2102";

    int group_size = 0;
    const char *group_sids[] = {};

    test_ad_gpo_ace_includes_client_sid(user_sid, host_sid, group_sids,
                                        group_size, ace_dom_sid, true);
}

uint8_t test_sid_data[] = {
0x01, 0x00, 0x04, 0x9c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x14, 0x00, 0x00, 0x00, 0x04, 0x00, 0x34, 0x01, 0x0a, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
0xbd, 0x00, 0x0e, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
0xda, 0x0e, 0xba, 0x60, 0x0f, 0xa2, 0xf4, 0x55, 0xb5, 0x57, 0x47, 0xf8, 0x00, 0x02, 0x00, 0x00,
0x00, 0x0a, 0x24, 0x00, 0xff, 0x00, 0x0f, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
0x15, 0x00, 0x00, 0x00, 0xda, 0x0e, 0xba, 0x60, 0x0f, 0xa2, 0xf4, 0x55, 0xb5, 0x57, 0x47, 0xf8,
0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00, 0xbd, 0x00, 0x0e, 0x00, 0x01, 0x05, 0x00, 0x00,
0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xda, 0x0e, 0xba, 0x60, 0x0f, 0xa2, 0xf4, 0x55,
0xb5, 0x57, 0x47, 0xf8, 0x07, 0x02, 0x00, 0x00, 0x00, 0x0a, 0x24, 0x00, 0xff, 0x00, 0x0f, 0x00,
0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00, 0xda, 0x0e, 0xba, 0x60,
0x0f, 0xa2, 0xf4, 0x55, 0xb5, 0x57, 0x47, 0xf8, 0x07, 0x02, 0x00, 0x00, 0x00, 0x00, 0x24, 0x00,
0xbd, 0x00, 0x0e, 0x00, 0x01, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x15, 0x00, 0x00, 0x00,
0xda, 0x0e, 0xba, 0x60, 0x0f, 0xa2, 0xf4, 0x55, 0xb5, 0x57, 0x47, 0xf8, 0x00, 0x02, 0x00, 0x00,
0x00, 0x0a, 0x14, 0x00, 0xff, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03,
0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x14, 0x00, 0xff, 0x00, 0x0f, 0x00, 0x01, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x05, 0x12, 0x00, 0x00, 0x00, 0x00, 0x02, 0x14, 0x00, 0x94, 0x00, 0x02, 0x00,
0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05, 0x0b, 0x00, 0x00, 0x00, 0x05, 0x02, 0x28, 0x00,
0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x8f, 0xfd, 0xac, 0xed, 0xb3, 0xff, 0xd1, 0x11,
0xb4, 0x1d, 0x00, 0xa0, 0xc9, 0x68, 0xf9, 0x39, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x05,
0x0b, 0x00, 0x00, 0x00, 0x00, 0x02, 0x14, 0x00, 0x94, 0x00, 0x02, 0x00, 0x01, 0x01, 0x00, 0x00,
0x00, 0x00, 0x00, 0x05, 0x09, 0x00, 0x00, 0x00
};

void test_ad_gpo_parse_sd(void **state)
{
    int ret;
    struct security_descriptor *sd = NULL;

    ret = ad_gpo_parse_sd(test_ctx, NULL, 0, &sd);
    assert_int_equal(ret, EINVAL);

    ret = ad_gpo_parse_sd(test_ctx, test_sid_data, sizeof(test_sid_data), &sd);
    assert_int_equal(ret, EOK);
    assert_non_null(sd);
    assert_int_equal(sd->revision, 1);
    assert_int_equal(sd->type, 39940);
    assert_null(sd->owner_sid);
    assert_null(sd->group_sid);
    assert_null(sd->sacl);
    assert_non_null(sd->dacl);
    assert_int_equal(sd->dacl->revision, 4);
    assert_int_equal(sd->dacl->size, 308);
    assert_int_equal(sd->dacl->num_aces, 10);
    assert_int_equal(sd->dacl->aces[0].type, 0);
    assert_int_equal(sd->dacl->aces[0].flags, 0);
    assert_int_equal(sd->dacl->aces[0].size, 36);
    assert_int_equal(sd->dacl->aces[0].access_mask, 917693);
    /* There are more components and ACEs in the security_descriptor struct
     * which are not checked here. */

    talloc_free(sd);
}

errno_t ad_gpo_parse_ini_file(const char *smb_path, int *_gpt_version);

void test_ad_gpo_parse_ini_file(void **state)
{
    int version = -1;

    ad_gpo_parse_ini_file(ABS_SRC_DIR"/src/tests/cmocka/GPT.INI", &version);

    assert_int_equal(version, 6);
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
        cmocka_unit_test_setup_teardown(test_populate_som_list_plain,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_populate_som_list_malformed,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_populate_gplink_list_plain,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_populate_gplink_list_with_ignored,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_populate_gplink_list_with_allow_enforced,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_populate_gplink_list_malformed,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_ad_gpo_ace_includes_client_sid_true,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_ad_gpo_ace_includes_client_sid_false,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_ad_gpo_ace_includes_host_sid_true,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_ad_gpo_parse_sd,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
        cmocka_unit_test_setup_teardown(test_ad_gpo_parse_ini_file,
                                        ad_gpo_test_setup,
                                        ad_gpo_test_teardown),
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
