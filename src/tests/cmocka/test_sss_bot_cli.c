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

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <string.h>
#include <cmocka.h>

#include "util/sss_bot.h"

static void test_sss_bot_cli__parse_valid(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~1000~abc123", &bot);
    assert_int_equal(ret, 0);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~1000~abc123");
    assert_string_equal(bot->name, "BOT~1000~abc123");
    assert_string_equal(bot->random, "abc123");
    assert_int_equal(bot->uid, 1000);

    sss_bot_cli_free(bot);
}

static void test_sss_bot_cli__parse_with_realm(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~1000~abc123@EXAMPLE.COM", &bot);
    assert_int_equal(ret, 0);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~1000~abc123@EXAMPLE.COM");
    assert_string_equal(bot->name, "BOT~1000~abc123");
    assert_string_equal(bot->random, "abc123");
    assert_int_equal(bot->uid, 1000);

    sss_bot_cli_free(bot);
}

static void test_sss_bot_cli__parse_with_domain(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~5001~xyz@example.com", &bot);
    assert_int_equal(ret, 0);
    assert_non_null(bot);
    assert_string_equal(bot->input, "BOT~5001~xyz@example.com");
    assert_string_equal(bot->name, "BOT~5001~xyz");
    assert_string_equal(bot->random, "xyz");
    assert_int_equal(bot->uid, 5001);

    sss_bot_cli_free(bot);
}

static void test_sss_bot_cli__parse_large_uid(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~4294967295~rnd", &bot);
    assert_int_equal(ret, 0);
    assert_non_null(bot);
    assert_int_equal(bot->uid, UINT32_MAX);

    sss_bot_cli_free(bot);
}

static void test_sss_bot_cli__parse_random_with_dashes(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~1000~abc-def-ghi", &bot);
    assert_int_equal(ret, 0);
    assert_non_null(bot);
    assert_string_equal(bot->random, "abc-def-ghi");
    assert_int_equal(bot->uid, 1000);

    sss_bot_cli_free(bot);
}

static void test_sss_bot_cli__parse_null_input(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse(NULL, &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_not_bot(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("user@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_empty_string(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_prefix_only(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_no_random(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~1000~", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_no_random_with_realm(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~1000~@EXAMPLE.COM", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_zero(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~0~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_overflow(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~4294967296~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_not_numeric(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~abc~random", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_leading_space(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~ 1000~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_leading_plus(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~+1000~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_uid_negative(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~-1~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

static void test_sss_bot_cli__parse_no_uid_no_random(void **state)
{
    struct sss_bot *bot = NULL;
    int ret;

    ret = sss_bot_cli_parse("BOT~abc", &bot);
    assert_int_equal(ret, EINVAL);
    assert_null(bot);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_bot_cli__parse_valid),
        cmocka_unit_test(test_sss_bot_cli__parse_with_realm),
        cmocka_unit_test(test_sss_bot_cli__parse_with_domain),
        cmocka_unit_test(test_sss_bot_cli__parse_large_uid),
        cmocka_unit_test(test_sss_bot_cli__parse_random_with_dashes),
        cmocka_unit_test(test_sss_bot_cli__parse_null_input),
        cmocka_unit_test(test_sss_bot_cli__parse_not_bot),
        cmocka_unit_test(test_sss_bot_cli__parse_empty_string),
        cmocka_unit_test(test_sss_bot_cli__parse_prefix_only),
        cmocka_unit_test(test_sss_bot_cli__parse_no_random),
        cmocka_unit_test(test_sss_bot_cli__parse_no_random_with_realm),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_zero),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_overflow),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_not_numeric),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_leading_space),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_leading_plus),
        cmocka_unit_test(test_sss_bot_cli__parse_uid_negative),
        cmocka_unit_test(test_sss_bot_cli__parse_no_uid_no_random),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
