/*
    SSSD

    util-tests.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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

#include <popt.h>
#include <talloc.h>
#include <check.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include "util/util.h"
#include "util/sss_utf8.h"
#include "util/murmurhash3.h"
#include "tests/common.h"

#define FILENAME_TEMPLATE "tests-atomicio-XXXXXX"
char *filename;
int atio_fd;

START_TEST(test_add_string_to_list)
{
    int ret;

    char **list = NULL;

    ret = add_string_to_list(NULL, NULL, NULL);
    fail_unless(ret == EINVAL, "NULL input accepted");

    ret = add_string_to_list(global_talloc_context, "ABC", &list);
    fail_unless(ret == EOK, "Adding string to non-existing list failed.");
    fail_unless(list != NULL, "No new list created.");
    fail_unless(list[0] != NULL, "String not added to new list.");
    fail_unless(strcmp(list[0], "ABC") == 0,
                "Wrong string added to newly created list.");
    fail_unless(list[1] == NULL,
                "Missing terminating NULL in newly created list.");

    ret = add_string_to_list(global_talloc_context, "DEF", &list);
    fail_unless(ret == EOK, "Adding string to list failed.");
    fail_unless(list != NULL, "No list returned.");
    fail_unless(strcmp(list[0], "ABC") == 0, "Wrong first string in new list.");
    fail_unless(strcmp(list[1], "DEF") == 0, "Wrong string added to list.");
    fail_unless(list[2] == NULL, "Missing terminating NULL.");

    list[0] = NULL;
    ret = add_string_to_list(global_talloc_context, "ABC", &list);
    fail_unless(ret == EOK, "Adding string to empty list failed.");
    fail_unless(list != NULL, "No list returned.");
    fail_unless(list[0] != NULL, "String not added to empty list.");
    fail_unless(strcmp(list[0], "ABC") == 0,
                "Wrong string added to empty list.");
    fail_unless(list[1] == NULL,
                "Missing terminating NULL in newly created list.");

    talloc_free(list);
}
END_TEST

START_TEST(test_string_in_list)
{
    bool is_in;
    char *empty_list[] = {NULL};
    char *list[] = {discard_const("ABC"),
                    discard_const("DEF"),
                    discard_const("GHI"),
                    NULL};

    is_in = string_in_list(NULL, NULL, false);
    fail_unless(!is_in, "NULL string is in NULL list.");

    is_in = string_in_list(NULL, empty_list, false);
    fail_unless(!is_in, "NULL string is in empty list.");

    is_in = string_in_list(NULL, list, false);
    fail_unless(!is_in, "NULL string is in list.");

    is_in = string_in_list("ABC", NULL, false);
    fail_unless(!is_in, "String is in NULL list.");

    is_in = string_in_list("ABC", empty_list, false);
    fail_unless(!is_in, "String is in empty list.");

    is_in = string_in_list("ABC", list, false);
    fail_unless(is_in, "String is not list.");

    is_in = string_in_list("abc", list, false);
    fail_unless(is_in, "String is not case in-sensitive list.");

    is_in = string_in_list("abc", list, true);
    fail_unless(!is_in, "Wrong string found in case sensitive list.");

    is_in = string_in_list("123", list, false);
    fail_unless(!is_in, "Wrong string found in list.");

}
END_TEST

START_TEST(test_parse_args)
{
    struct pa_testcase {
        const char *argstr;
        const char **parsed;
    };

    TALLOC_CTX *test_ctx;
    int i, ii;
    int ret;
    char **parsed;
    char **only_ret;
    char **only_exp;
    char **both;

    test_ctx = talloc_new(NULL);

    /* Positive tests */
    const char *parsed1[] = { "foo", NULL };
    const char *parsed2[] = { "foo", "a", NULL };
    const char *parsed3[] = { "foo", "b", NULL };
    const char *parsed4[] = { "foo", "a c", NULL };
    const char *parsed5[] = { "foo", "a", "d", NULL };
    const char *parsed6[] = { "foo", "a", "e", NULL };
    const char *parsed7[] = { "foo", "a", "f", NULL };
    const char *parsed8[] = { "foo", "a\tg", NULL };
    struct pa_testcase tc[] = {
        { "foo", parsed1 },
        { "foo a", parsed2 },
        { "foo  b", parsed3 },
        { "foo a\\ c", parsed4 },
        { "foo a d ", parsed5 },
        { "foo   a   e   ", parsed6 },
        { "foo	a	 	f 	", parsed7 },
        { "foo a\\\tg", parsed8 },
        { NULL, NULL }
    };

    for (i=0; tc[i].argstr != NULL; i++) {
        parsed = parse_args(tc[i].argstr);
        fail_if(parsed == NULL && tc[i].parsed != NULL,
                "Could not parse correct argument string '%s'\n");

        ret = diff_string_lists(test_ctx, parsed, discard_const(tc[i].parsed),
                                &only_ret, &only_exp, &both);
        fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
        fail_unless(only_ret[0] == NULL, "The parser returned more data than expected\n");
        fail_unless(only_exp[0] == NULL, "The parser returned less data than expected\n");

        for (ii = 0; parsed[ii]; ii++) free(parsed[ii]);
        free(parsed);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_diff_string_lists)
{
    TALLOC_CTX *test_ctx;
    char **l1;
    char **l2;
    char **l3;
    char **only_l1;
    char **only_l2;
    char **both;
    int ret;

    test_ctx = talloc_new(NULL);

    /* Test with all values returned */
    l1 = talloc_array(test_ctx, char *, 4);
    l1[0] = talloc_strdup(l1, "a");
    l1[1] = talloc_strdup(l1, "b");
    l1[2] = talloc_strdup(l1, "c");
    l1[3] = NULL;

    l2 = talloc_array(test_ctx, char *, 4);
    l2[0] = talloc_strdup(l1, "d");
    l2[1] = talloc_strdup(l1, "c");
    l2[2] = talloc_strdup(l1, "b");
    l2[3] = NULL;

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(strcmp(both[0], "c") == 0, "Missing \"c\" from both");
    fail_unless(strcmp(both[1], "b") == 0, "Missing \"b\" from both");
    fail_unless(both[2] == NULL, "both not NULL-terminated");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with restricted return values */
    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, &only_l2, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            &only_l1, NULL, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(only_l1[1] == NULL, "only_l1 not NULL-terminated");
    fail_unless(only_l2 == NULL, "Nothing returned to only_l2");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    ret = diff_string_lists(test_ctx,
                            l1, l2,
                            NULL, &only_l2, NULL);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[1] == NULL, "only_l2 not NULL-terminated");
    fail_unless(only_l1 == NULL, "Nothing returned to only_l1");
    fail_unless(both == NULL, "Nothing returned to both");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with no overlap */
    l3 = talloc_array(test_ctx, char *, 4);
    l3[0] = talloc_strdup(l1, "d");
    l3[1] = talloc_strdup(l1, "e");
    l3[2] = talloc_strdup(l1, "f");
    l3[3] = NULL;

    ret = diff_string_lists(test_ctx,
                            l1, l3,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(strcmp(only_l1[1], "b") == 0, "Missing \"b\" from only_l1");
    fail_unless(strcmp(only_l1[2], "c") == 0, "Missing \"c\" from only_l1");
    fail_unless(only_l1[3] == NULL, "only_l1 not NULL-terminated");
    fail_unless(strcmp(only_l2[0], "d") == 0, "Missing \"f\" from only_l2");
    fail_unless(strcmp(only_l2[1], "e") == 0, "Missing \"e\" from only_l2");
    fail_unless(strcmp(only_l2[2], "f") == 0, "Missing \"d\" from only_l2");
    fail_unless(only_l2[3] == NULL, "only_l2 not NULL-terminated");
    fail_unless(both[0] == NULL, "both should have zero entries");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with 100% overlap */
    ret = diff_string_lists(test_ctx,
                            l1, l1,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(only_l1[0] == NULL, "only_l1 should have zero entries");
    fail_unless(only_l2[0] == NULL, "only_l2 should have zero entries");
    fail_unless(strcmp(both[0], "a") == 0, "Missing \"a\" from both");
    fail_unless(strcmp(both[1], "b") == 0, "Missing \"b\" from both");
    fail_unless(strcmp(both[2], "c") == 0, "Missing \"c\" from both");
    fail_unless(both[3] == NULL, "both is not NULL-terminated");

    talloc_zfree(only_l1);
    talloc_zfree(only_l2);
    talloc_zfree(both);

    /* Test with no second list */
    ret = diff_string_lists(test_ctx,
                            l1, NULL,
                            &only_l1, &only_l2, &both);

    fail_unless(ret == EOK, "diff_string_lists returned error [%d]", ret);
    fail_unless(strcmp(only_l1[0], "a") == 0, "Missing \"a\" from only_l1");
    fail_unless(strcmp(only_l1[1], "b") == 0, "Missing \"b\" from only_l1");
    fail_unless(strcmp(only_l1[2], "c") == 0, "Missing \"c\" from only_l1");
    fail_unless(only_l1[3] == NULL, "only_l1 not NULL-terminated");
    fail_unless(only_l2[0] == NULL, "only_l2 should have zero entries");
    fail_unless(both[0] == NULL, "both should have zero entries");

    talloc_free(test_ctx);
}
END_TEST


START_TEST(test_sss_filter_sanitize)
{
    errno_t ret;
    char *sanitized = NULL;

    TALLOC_CTX *test_ctx = talloc_new(NULL);
    fail_if (test_ctx == NULL, "Out of memory");

    const char no_specials[] = "username";
    ret = sss_filter_sanitize(test_ctx, no_specials, &sanitized);
    fail_unless(ret == EOK, "no_specials error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(no_specials, sanitized)==0,
                "Expected [%s], got [%s]",
                no_specials, sanitized);

    const char has_asterisk[] = "*username";
    const char has_asterisk_expected[] = "\\2ausername";
    ret = sss_filter_sanitize(test_ctx, has_asterisk, &sanitized);
    fail_unless(ret == EOK, "has_asterisk error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(has_asterisk_expected, sanitized)==0,
                "Expected [%s], got [%s]",
                has_asterisk_expected, sanitized);

    const char has_lparen[] = "user(name";
    const char has_lparen_expected[] = "user\\28name";
    ret = sss_filter_sanitize(test_ctx, has_lparen, &sanitized);
    fail_unless(ret == EOK, "has_lparen error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(has_lparen_expected, sanitized)==0,
                "Expected [%s], got [%s]",
                has_lparen_expected, sanitized);

    const char has_rparen[] = "user)name";
    const char has_rparen_expected[] = "user\\29name";
    ret = sss_filter_sanitize(test_ctx, has_rparen, &sanitized);
    fail_unless(ret == EOK, "has_rparen error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(has_rparen_expected, sanitized)==0,
                "Expected [%s], got [%s]",
                has_rparen_expected, sanitized);

    const char has_backslash[] = "username\\";
    const char has_backslash_expected[] = "username\\5c";
    ret = sss_filter_sanitize(test_ctx, has_backslash, &sanitized);
    fail_unless(ret == EOK, "has_backslash error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(has_backslash_expected, sanitized)==0,
                "Expected [%s], got [%s]",
                has_backslash_expected, sanitized);

    const char has_all[] = "\\(user)*name";
    const char has_all_expected[] = "\\5c\\28user\\29\\2aname";
    ret = sss_filter_sanitize(test_ctx, has_all, &sanitized);
    fail_unless(ret == EOK, "has_all error [%d][%s]",
                ret, strerror(ret));
    fail_unless(strcmp(has_all_expected, sanitized)==0,
                "Expected [%s], got [%s]",
                has_all_expected, sanitized);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_size_t_overflow)
{
    fail_unless(!SIZE_T_OVERFLOW(1, 1), "unexpected overflow");
    fail_unless(!SIZE_T_OVERFLOW(SIZE_T_MAX, 0), "unexpected overflow");
    fail_unless(!SIZE_T_OVERFLOW(SIZE_T_MAX-10, 10), "unexpected overflow");
    fail_unless(SIZE_T_OVERFLOW(SIZE_T_MAX, 1), "overflow not detected");
    fail_unless(SIZE_T_OVERFLOW(SIZE_T_MAX, SIZE_T_MAX),
                "overflow not detected");
    fail_unless(SIZE_T_OVERFLOW(SIZE_T_MAX, ULLONG_MAX),
                "overflow not detected");
    fail_unless(SIZE_T_OVERFLOW(SIZE_T_MAX, -10), "overflow not detected");
}
END_TEST

START_TEST(test_utf8_lowercase)
{
    const uint8_t munchen_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
    const uint8_t munchen_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
    uint8_t *lcase;
    size_t nlen;

    lcase = sss_utf8_tolower(munchen_utf8_upcase,
                             strlen((const char *)munchen_utf8_upcase),
                             &nlen);
    fail_if(strlen((const char *) munchen_utf8_upcase) != nlen); /* This is not true for utf8 strings in general */
    fail_if(memcmp(lcase, munchen_utf8_lowcase, nlen));
    sss_utf8_free(lcase);
}
END_TEST

START_TEST(test_utf8_talloc_lowercase)
{
    const uint8_t munchen_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
    const uint8_t munchen_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
    uint8_t *lcase;
    size_t nsize;

    TALLOC_CTX *test_ctx;
    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL);

    lcase = sss_tc_utf8_tolower(test_ctx, munchen_utf8_upcase,
                                strlen((const char *) munchen_utf8_upcase),
                                &nsize);
    fail_if(memcmp(lcase, munchen_utf8_lowcase, nsize));
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_utf8_talloc_str_lowercase)
{
    const uint8_t munchen_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
    const uint8_t munchen_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
    char *lcase;

    TALLOC_CTX *test_ctx;
    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL);

    lcase = sss_tc_utf8_str_tolower(test_ctx, (const char *) munchen_utf8_upcase);
    fail_if(memcmp(lcase, munchen_utf8_lowcase, strlen(lcase)));
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_utf8_caseeq)
{
    const uint8_t munchen_utf8_upcase[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
    const uint8_t munchen_utf8_lowcase[] = { 'm', 0xC3, 0xBC, 'n', 'c', 'h', 'e', 'n', 0x0 };
    const uint8_t czech_utf8_lowcase[] = { 0xC4, 0x8D, 'e', 'c', 'h', 0x0 };
    const uint8_t czech_utf8_upcase[] = { 0xC4, 0x8C, 'e', 'c', 'h', 0x0 };
    const uint8_t czech_utf8_lowcase_neg[] = { 0xC4, 0x8E, 'e', 'c', 'h', 0x0 };
    errno_t ret;

    ret = sss_utf8_case_eq(munchen_utf8_upcase, munchen_utf8_lowcase);
    fail_unless(ret == EOK, "Latin 1 Supplement comparison failed\n");

    ret = sss_utf8_case_eq(czech_utf8_upcase, czech_utf8_lowcase);
    fail_unless(ret == EOK, "Latin Extended A comparison failed\n");

    ret = sss_utf8_case_eq(czech_utf8_upcase, czech_utf8_lowcase_neg);
    fail_if(ret == EOK, "Negative test succeeded\n");
}
END_TEST

START_TEST(test_utf8_check)
{
    const char *invalid = "ad\351la\357d";
    const uint8_t valid[] = { 'M', 0xC3, 0x9C, 'N', 'C', 'H', 'E', 'N', 0x0 };
    bool ret;

    ret = sss_utf8_check(valid, strlen((const char *) valid));
    fail_unless(ret == true, "Positive test failed\n");

    ret = sss_utf8_check((const uint8_t *) invalid, strlen(invalid));
    fail_unless(ret == false, "Negative test succeeded\n");
}
END_TEST

START_TEST(test_murmurhash3_check)
{
    const char *tests[6] = { "1052800007", "1052800008", "1052800000",
                             "abcdefghijk", "abcdefghili", "abcdefgh000" };
    uint32_t results[6];
    int i, j;

    for (i = 0; i< 6; i++) {
        results[i] = murmurhash3(tests[i],
                                 strlen(tests[i]),
                                 0xdeadbeef);
        for (j = 0; j < i; j++) {
            fail_if(results[i] == results[j]);
        }
    }
}
END_TEST

START_TEST(test_murmurhash3_random)
{
    char test[16];
    uint32_t result1;
    uint32_t result2;
    unsigned int init_seed;
    unsigned int seed;
    size_t len;
    int i;

    /* generate a random string so each time we test with different values */
    init_seed = time(0);
    seed = init_seed;
    /* use also random length (min len = 1) */
    len = 1 + rand_r(&seed) % 14;
    for (i = 0; i < len; i++) {
        test[i] = 1 + rand_r(&seed) % 254;
    }
    test[len] = '\0'; /* null terminate */

    fprintf(stdout, "test_murmurhash3_random seed: %d\n", init_seed);

    result1 = murmurhash3(test, len + 1, init_seed);
    result2 = murmurhash3(test, len + 1, init_seed);
    fail_if(result1 != result2);
}
END_TEST

void setup_atomicio(void)
{
    int ret;
    mode_t old_umask;

    filename = strdup(FILENAME_TEMPLATE);
    fail_unless(filename != NULL, "strdup failed");

    atio_fd = -1;
    old_umask = umask(077);
    ret = mkstemp(filename);
    umask(old_umask);
    fail_unless(ret != -1, "mkstemp failed [%d][%s]", errno, strerror(errno));
    atio_fd = ret;
}

void teardown_atomicio(void)
{
    int ret;

    if (atio_fd != -1) {
        ret = close(atio_fd);
        fail_unless(ret == 0, "close failed [%d][%s]", errno, strerror(errno));
    }

    fail_unless(filename != NULL, "unknown filename");
    ret = unlink(filename);
    free(filename);
    fail_unless(ret == 0, "unlink failed [%d][%s]", errno, strerror(errno));
}

START_TEST(test_atomicio_read_from_file)
{
    const ssize_t bufsize = 64;
    char buf[64];
    int fd;
    ssize_t numread;
    errno_t ret;

    fd = open("/dev/zero", O_RDONLY);
    fail_if(fd == -1, "Cannot open /dev/zero");

    errno = 0;
    numread = sss_atomic_read_s(fd, buf, bufsize);
    ret = errno;

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(numread == bufsize,
                "Read %d bytes expected %d\n", numread, bufsize);
    close(fd);
}
END_TEST

START_TEST(test_atomicio_read_from_small_file)
{
    char wbuf[] = "foobar";
    ssize_t wsize = strlen(wbuf)+1;
    ssize_t numwritten;
    char rbuf[64];
    ssize_t numread;
    errno_t ret;

    fail_if(atio_fd < 0, "No fd to test?\n");

    errno = 0;
    numwritten = sss_atomic_write_s(atio_fd, wbuf, wsize);
    ret = errno;

    fail_unless(ret == 0, "Error %d while writing\n", ret);
    fail_unless(numwritten == wsize,
                "Wrote %d bytes expected %d\n", numwritten, wsize);

    fsync(atio_fd);
    lseek(atio_fd, 0, SEEK_SET);

    errno = 0;
    numread = sss_atomic_read_s(atio_fd, rbuf, 64);
    ret = errno;

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(numread == numwritten,
                "Read %d bytes expected %d\n", numread, numwritten);
}
END_TEST

START_TEST(test_atomicio_read_from_large_file)
{
    char wbuf[] = "123456781234567812345678";
    ssize_t wsize = strlen(wbuf)+1;
    ssize_t numwritten;
    char rbuf[8];
    ssize_t numread;
    ssize_t total;
    errno_t ret;

    fail_if(atio_fd < 0, "No fd to test?\n");

    errno = 0;
    numwritten = sss_atomic_write_s(atio_fd, wbuf, wsize);
    ret = errno;

    fail_unless(ret == 0, "Error %d while writing\n", ret);
    fail_unless(numwritten == wsize,
                "Wrote %d bytes expected %d\n", numwritten, wsize);

    fsync(atio_fd);
    lseek(atio_fd, 0, SEEK_SET);

    total = 0;
    do {
        errno = 0;
        numread = sss_atomic_read_s(atio_fd, rbuf, 8);
        ret = errno;

        fail_if(numread == -1, "Read error %d: %s\n", ret, strerror(ret));
        total += numread;
    } while (numread != 0);

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(total == numwritten,
                "Read %d bytes expected %d\n", numread, numwritten);
}
END_TEST

START_TEST(test_atomicio_read_exact_sized_file)
{
    char wbuf[] = "12345678";
    ssize_t wsize = strlen(wbuf)+1;
    ssize_t numwritten;
    char rbuf[9];
    ssize_t numread;
    errno_t ret;

    fail_if(atio_fd < 0, "No fd to test?\n");

    errno = 0;
    numwritten = sss_atomic_write_s(atio_fd, wbuf, wsize);
    ret = errno;

    fail_unless(ret == 0, "Error %d while writing\n", ret);
    fail_unless(numwritten == wsize,
                "Wrote %d bytes expected %d\n", numwritten, wsize);

    fsync(atio_fd);
    lseek(atio_fd, 0, SEEK_SET);

    errno = 0;
    numread = sss_atomic_read_s(atio_fd, rbuf, 9);
    ret = errno;

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(numread == numwritten,
                "Read %d bytes expected %d\n", numread, numwritten);

    fail_unless(rbuf[8] == '\0', "String not NULL terminated?");
    fail_unless(strcmp(wbuf, rbuf) == 0, "Read something else than wrote?");

    /* We've reached end-of-file, next read must return 0 */
    errno = 0;
    numread = sss_atomic_read_s(atio_fd, rbuf, 9);
    ret = errno;

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(numread == 0, "More data to read?");
}
END_TEST

START_TEST(test_atomicio_read_from_empty_file)
{
    char buf[64];
    int fd;
    ssize_t numread;
    errno_t ret;

    fd = open("/dev/null", O_RDONLY);
    fail_if(fd == -1, "Cannot open /dev/null");

    errno = 0;
    numread = sss_atomic_read_s(fd, buf, 64);
    ret = errno;

    fail_unless(ret == 0, "Error %d while reading\n", ret);
    fail_unless(numread == 0,
                "Read %d bytes expected 0\n", numread);
    close(fd);
}
END_TEST

Suite *util_suite(void)
{
    Suite *s = suite_create("util");

    TCase *tc_util = tcase_create("util");

    tcase_add_checked_fixture(tc_util,
                              leak_check_setup,
                              leak_check_teardown);
    tcase_add_test (tc_util, test_diff_string_lists);
    tcase_add_test (tc_util, test_sss_filter_sanitize);
    tcase_add_test (tc_util, test_size_t_overflow);
    tcase_add_test (tc_util, test_parse_args);
    tcase_add_test (tc_util, test_add_string_to_list);
    tcase_add_test (tc_util, test_string_in_list);
    tcase_set_timeout(tc_util, 60);

    TCase *tc_utf8 = tcase_create("utf8");
    tcase_add_test (tc_utf8, test_utf8_lowercase);
    tcase_add_test (tc_utf8, test_utf8_talloc_lowercase);
    tcase_add_test (tc_utf8, test_utf8_talloc_str_lowercase);
    tcase_add_test (tc_utf8, test_utf8_caseeq);
    tcase_add_test (tc_utf8, test_utf8_check);

    tcase_set_timeout(tc_utf8, 60);

    TCase *tc_mh3 = tcase_create("murmurhash3");
    tcase_add_test (tc_mh3, test_murmurhash3_check);
    tcase_add_test (tc_mh3, test_murmurhash3_random);
    tcase_set_timeout(tc_mh3, 60);

    TCase *tc_atomicio = tcase_create("atomicio");
    tcase_add_checked_fixture (tc_atomicio,
                               setup_atomicio,
                               teardown_atomicio);
    tcase_add_test(tc_atomicio, test_atomicio_read_from_file);
    tcase_add_test(tc_atomicio, test_atomicio_read_from_small_file);
    tcase_add_test(tc_atomicio, test_atomicio_read_from_large_file);
    tcase_add_test(tc_atomicio, test_atomicio_read_exact_sized_file);
    tcase_add_test(tc_atomicio, test_atomicio_read_from_empty_file);

    suite_add_tcase (s, tc_util);
    suite_add_tcase (s, tc_utf8);
    suite_add_tcase (s, tc_mh3);
    suite_add_tcase (s, tc_atomicio);

    return s;
}

int main(int argc, const char *argv[])
{
    int opt;
    int failure_count;
    poptContext pc;
    Suite *s = util_suite();
    SRunner *sr = srunner_create (s);

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed (sr);
    srunner_free (sr);
    if (failure_count == 0) {
        return EXIT_SUCCESS;
    }
    return  EXIT_FAILURE;
}
