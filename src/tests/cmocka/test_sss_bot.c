/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2026 Red Hat

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

#include <string.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "util/sss_bot.h"

struct test_state {
    TALLOC_CTX *mem_ctx;
};

static int setup(void **state)
{
    struct test_state *ts = NULL;

    assert_true(leak_check_setup());

    ts = talloc(global_talloc_context, struct test_state);
    assert_non_null(ts);

    ts->mem_ctx = ts;

    check_leaks_push(ts);
    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);

    assert_true(check_leaks_pop(ts));
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sss_bot__parse_valid(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~abc123", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~1000~abc123");
    assert_string_equal(bot->name, "BOT~1000~abc123");
    assert_string_equal(bot->random, "abc123");
    assert_int_equal(bot->uid, 1000);

    talloc_free(bot);
}

static void test_sss_bot__parse_with_realm(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~abc123@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~1000~abc123@EXAMPLE.COM");
    assert_string_equal(bot->name, "BOT~1000~abc123");
    assert_string_equal(bot->random, "abc123");
    assert_int_equal(bot->uid, 1000);

    talloc_free(bot);
}

static void test_sss_bot__parse_with_domain(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~5001~xyz@example.com", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~5001~xyz@example.com");
    assert_string_equal(bot->name, "BOT~5001~xyz");
    assert_string_equal(bot->random, "xyz");
    assert_int_equal(bot->uid, 5001);

    talloc_free(bot);
}

static void test_sss_bot__parse_large_uid(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~4294967295~rnd", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);
    assert_int_equal(bot->uid, UINT32_MAX);

    talloc_free(bot);
}

static void test_sss_bot__parse_random_with_dashes(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~abc-def-ghi", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);
    assert_string_equal(bot->random, "abc-def-ghi");
    assert_int_equal(bot->uid, 1000);

    talloc_free(bot);
}

static void test_sss_bot__parse_null_input(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, NULL, &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_not_bot(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "user@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_empty_string(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_prefix_only(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_no_random(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_no_random_with_realm(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_zero(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~0~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_overflow(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~4294967296~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_not_numeric(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~abc~random", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_leading_space(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~ 1000~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_leading_plus(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~+1000~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_uid_negative(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~-1~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__parse_no_uid_no_random(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot__copy(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_bot *bot = NULL;
    struct sss_bot *copy = NULL;
    errno_t ret;

    ret = sss_bot_parse(ts->mem_ctx, "BOT~1000~abc123@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EOK);
    assert_non_null(bot);

    copy = sss_bot_copy(ts->mem_ctx, bot);
    assert_non_null(copy);

    assert_string_equal(copy->input, bot->input);
    assert_string_equal(copy->name, bot->name);
    assert_string_equal(copy->random, bot->random);
    assert_int_equal(copy->uid, bot->uid);

    assert_ptr_not_equal(copy->input, bot->input);
    assert_ptr_not_equal(copy->name, bot->name);
    assert_ptr_not_equal(copy->random, bot->random);

    talloc_free(bot);

    assert_string_equal(copy->input, "BOT~1000~abc123@EXAMPLE.COM");
    assert_string_equal(copy->name, "BOT~1000~abc123");
    assert_string_equal(copy->random, "abc123");
    assert_int_equal(copy->uid, 1000);

    talloc_free(copy);
}

static void test_sss_bot__copy_null(void **state)
{
    struct sss_bot *copy = NULL;

    copy = sss_bot_copy(NULL, NULL);
    assert_null(copy);
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
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_valid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_with_realm,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_with_domain,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_large_uid,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_random_with_dashes,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_null_input,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_not_bot,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_empty_string,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_prefix_only,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_no_random,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_no_random_with_realm,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_zero,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_overflow,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_not_numeric,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_leading_space,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_leading_plus,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_uid_negative,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__parse_no_uid_no_random,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__copy,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_bot__copy_null,
                                        setup, teardown),
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
