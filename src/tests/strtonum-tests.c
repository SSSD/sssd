/*
   SSSD

   InfoPipe

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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

#include <stdlib.h>
#include <check.h>
#include <errno.h>
#include <popt.h>
#include "util/util.h"
#include "util/strtonum.h"
#include "tests/common.h"

/********************
 * Utility routines *
 ********************/
#define EXPECT_UNSET_ERRNO(error) \
    do { \
        ck_assert_msg(error == 0, "errno unexpectedly set to %d[%s]", \
                                error, strerror(error)); \
    } while(0)

#define CHECK_RESULT(expected, actual) \
    do { \
        ck_assert_msg(actual == expected, "Expected %jd, got %jd", \
                                        (intmax_t)expected, (intmax_t)actual); \
    } while(0)

#define CHECK_ERRNO(expected, actual) \
    do { \
        ck_assert_msg(actual == expected, "Expected errno %d[%s], got %d[%s]", \
                                        expected, strerror(expected), \
                                        actual, strerror(actual)); \
    } while(0)

#define CHECK_ENDPTR(expected, actual) \
    do { \
        ck_assert_msg(actual == expected, "Expected endptr %p, got %p", \
                                         expected, actual); \
    } while(0)

#define CHECK_ZERO_ENDPTR(endptr) \
    do { \
        ck_assert_msg(endptr && *endptr == '\0', "Invalid endptr"); \
    } while(0)

/******************
 * strtoint tests *
 ******************/

/* Base-10 */
START_TEST (test_strtoint32_pos_integer_base_10)
{
    int32_t result;
    const char *input = "123";
    int32_t expected = 123;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_neg_integer_base_10)
{
    int32_t result;
    const char *input = "-123";
    int32_t expected = -123;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_pos_integer_intmax_base_10)
{
    int32_t result;
    const char *input = "2147483647";
    int32_t expected = INT32_MAX;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_neg_integer_intmin_base_10)
{
    int32_t result;
    const char *input = "-2147483648";
    int32_t expected = INT32_MIN;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_pos_integer_overflow_base_10)
{
    int32_t result;
    const char *input = "8589934592";
    int32_t expected = INT32_MAX;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_pos_integer_underflow_base_10)
{
    int32_t result;
    const char *input = "-8589934592";
    int32_t expected = INT32_MIN;
    char *endptr;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_mixed_alphanumeric_base_10)
{
    int32_t result;
    const char *input = "12b13";
    int32_t expected = 12;
    char *endptr;
    const char *expected_endptr = input+2;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_alphaonly_base_10)
{
    int32_t result;
    const char *input = "alpha";
    int32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_alphastart_base_10)
{
    int32_t result;
    const char *input = "alpha12345";
    int32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtoint32_emptystring_base_10)
{
    int32_t result;
    const char *input = "";
    int32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtoint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

/*******************
 * strtouint tests *
 *******************/

/* Base-10 */
START_TEST (test_strtouint32_pos_integer_base_10)
{
    uint32_t result;
    const char *input = "123";
    uint32_t expected = 123;
    char *endptr;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_neg_integer_base_10)
{
    uint32_t result;
    const char *input = "-123";
    uint32_t expected = UINT32_MAX;
    char *endptr;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_pos_integer_uintmax_base_10)
{
    uint32_t result;
    const char *input = "4294967295";
    uint32_t expected = UINT32_MAX;
    char *endptr;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST


START_TEST (test_strtouint32_pos_integer_overflow_base_10)
{
    uint32_t result;
    const char *input = "8589934592";
    uint32_t expected = UINT32_MAX;
    char *endptr;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_mixed_alphanumeric_base_10)
{
    uint32_t result;
    const char *input = "12b13";
    uint32_t expected = 12;
    char *endptr;
    const char *expected_endptr = input+2;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_alphaonly_base_10)
{
    uint32_t result;
    const char *input = "alpha";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_alphastart_base_10)
{
    uint32_t result;
    const char *input = "alpha12345";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint32_emptystring_base_10)
{
    uint32_t result;
    const char *input = "";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint32(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

/* Base-10 */
START_TEST (test_strtouint16_pos_integer_base_10)
{
    uint16_t result;
    const char *input = "123";
    uint16_t expected = 123;
    char *endptr;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_neg_integer_base_10)
{
    uint32_t result;
    const char *input = "-123";
    uint32_t expected = UINT16_MAX;
    char *endptr;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_pos_integer_uintmax_base_10)
{
    uint32_t result;
    const char *input = "65535";
    uint32_t expected = UINT16_MAX;
    char *endptr;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST


START_TEST (test_strtouint16_pos_integer_overflow_base_10)
{
    uint32_t result;
    const char *input = "131072";
    uint32_t expected = UINT16_MAX;
    char *endptr;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    CHECK_ERRNO(ERANGE, error);
    CHECK_ZERO_ENDPTR(endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_mixed_alphanumeric_base_10)
{
    uint32_t result;
    const char *input = "12b13";
    uint32_t expected = 12;
    char *endptr;
    const char *expected_endptr = input+2;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_alphaonly_base_10)
{
    uint32_t result;
    const char *input = "alpha";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_alphastart_base_10)
{
    uint32_t result;
    const char *input = "alpha12345";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST

START_TEST (test_strtouint16_emptystring_base_10)
{
    uint32_t result;
    const char *input = "";
    uint32_t expected = 0;
    char *endptr;
    const char *expected_endptr = input;
    errno_t error;

    result = strtouint16(input, &endptr, 10);
    error = errno;

    EXPECT_UNSET_ERRNO(error);
    CHECK_ENDPTR(expected_endptr, endptr);
    CHECK_RESULT(expected, result);
}
END_TEST


Suite *create_strtonum_suite(void)
{
    Suite *s = suite_create("strtonum");

    TCase *tc_strtoint32 = tcase_create("strtoint32 Tests");
    tcase_add_test(tc_strtoint32, test_strtoint32_pos_integer_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_neg_integer_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_pos_integer_intmax_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_neg_integer_intmin_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_pos_integer_overflow_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_pos_integer_underflow_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_mixed_alphanumeric_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_alphaonly_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_alphastart_base_10);
    tcase_add_test(tc_strtoint32, test_strtoint32_emptystring_base_10);

    TCase *tc_strtouint32 = tcase_create("strtouint32 Tests");
    tcase_add_test(tc_strtouint32, test_strtouint32_pos_integer_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_neg_integer_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_pos_integer_uintmax_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_pos_integer_overflow_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_mixed_alphanumeric_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_alphaonly_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_alphastart_base_10);
    tcase_add_test(tc_strtouint32, test_strtouint32_emptystring_base_10);

    TCase *tc_strtouint16 = tcase_create("strtouint16 Tests");
    tcase_add_test(tc_strtouint16, test_strtouint16_pos_integer_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_neg_integer_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_pos_integer_uintmax_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_pos_integer_overflow_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_mixed_alphanumeric_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_alphaonly_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_alphastart_base_10);
    tcase_add_test(tc_strtouint16, test_strtouint16_emptystring_base_10);

    /* Add all test cases to the suite */
    suite_add_tcase(s, tc_strtoint32);
    suite_add_tcase(s, tc_strtouint32);
    suite_add_tcase(s, tc_strtouint16);

    return s;
}


int main(int argc, const char *argv[]) {
    int opt;
    poptContext pc;
    int failure_count;
    Suite *strtonum_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        POPT_TABLEEND
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

    strtonum_suite = create_strtonum_suite();
    sr = srunner_create(strtonum_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
