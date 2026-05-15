/*
 * This file originated in realmd
 *
 * Copyright 2012 Red Hat Inc
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published
 * by the Free Software Foundation; either version 2 of the licence or (at
 * your option) any later version.
 *
 * See the included COPYING file for more information.
 *
 * Author: Stef Walter <stefw@redhat.com>
 */

#include "config.h"

#include "src/util/safe-format-string.h"

#include <check.h>
#include <popt.h>
#include <string.h>
#include <talloc.h>

#ifndef ck_assert_int_ge
#define ck_assert_int_ge(X, Y) _ck_assert_int(X, >=, Y)
#endif

#ifndef ck_assert_int_lt
#define ck_assert_int_lt(X, Y) _ck_assert_int(X, <, Y)
#endif

typedef struct {
    const char *format;
    const char *args[8];
    const char *result;
} Fixture;

static const Fixture fixtures[] = {
    {
      /* Just a bog standard string */
      "%s", { "blah", NULL, },
      "blah"
    },
    {
      /* Empty to print */
      "%s", { "", NULL, },
      ""
    },
    {
      /* Nothing to print */
      "", { "blah", NULL, },
      ""
    },
    {
      /* Width right aligned */
      "%8s", { "blah", NULL, },
      "    blah"
    },
    {
      /* Width left aligned */
      "whoop %-8s doo", { "dee", NULL, },
      "whoop dee      doo"
    },
    {
      /* Width space aligned (ignored) */
      "whoop % 8s doo", { "dee", NULL, },
      "whoop      dee doo"
    },
    {
      /* Width left space aligned (ignored) */
      "whoop % -8s doo", { "dee", NULL, },
      "whoop dee      doo"
    },
    {
      /* Precision 1 digit */
      "whoop %.3s doo", { "deedle-dee", NULL, },
      "whoop dee doo"
    },
    {
      /* Precision, N digits */
      "whoop %.10s doo", { "deedle-dee-deedle-do-deedle-dum", NULL, },
      "whoop deedle-dee doo"
    },
    {
      /* Precision, zero digits */
      "whoop %.s doo", { "deedle", NULL, },
      "whoop  doo"
    },
    {
      /* Multiple simple arguments */
      "space %s %s", { "man", "dances", NULL, },
      "space man dances"
    },
    {
      /* Literal percent */
      "100%% of space folk dance", { NULL, },
      "100% of space folk dance"
    },
    {
      /* Multiple simple arguments */
      "space %2$s %1$s", { "dances", "man", NULL, },
      "space man dances"
    },
    {
      /* Skipping an argument (not supported by standard printf) */
      "space %2$s dances", { "dances", "man", NULL, },
      "space man dances"
    },

    /* Failures start here */

    {
      /* Unsupported conversion */
      "%x", { "blah", NULL, },
      NULL
    },
    {
      /* Bad positional argument */
      "space %55$s dances", { "dances", "man", NULL, },
      NULL
    },
    {
      /* Zero positional argument */
      "space %0$s dances", { "dances", "man", NULL, },
      NULL
    },
    {
      /* Too many args used */
      "%s %s dances", { "space", NULL, },
      NULL
    },
    {
      /* Too many digits used */
      "%1234567890s dances", { "space", NULL, },
      NULL
    },
};


static void
callback(void *data, const char *piece, size_t len)
{
    char **str = data;
    *str = talloc_strndup_append(*str, piece, len);
}

START_TEST(test_safe_format_string_cb)
{
    const Fixture *fixture;
    char *out;
    int num_args;
    int ret;
    void *mem_ctx;

    fixture = &fixtures[_i];
    mem_ctx = talloc_init("safe-printf");

    for (num_args = 0; fixture->args[num_args] != NULL; )
        num_args++;

    out = talloc_strdup(mem_ctx, "");
    ret = safe_format_string_cb(callback, &out, fixture->format,
                                (const char * const*)fixture->args, num_args);
    if (fixture->result) {
        ck_assert_int_ge(ret, 0);
        ck_assert_str_eq(out, fixture->result);
        ck_assert_int_eq(ret, strlen(out));
    } else {
        ck_assert_int_lt(ret, 0);
    }

    talloc_free(mem_ctx);
}
END_TEST

START_TEST(test_safe_format_string)
{
    char buffer[8];
    int ret;

    ret = safe_format_string(buffer, 8, "%s", "space", "man", NULL);
    ck_assert_int_eq(ret, 5);
    ck_assert_str_eq(buffer, "space");

    ret = safe_format_string(buffer, 8, "", "space", "man", NULL);
    ck_assert_int_eq(ret, 0);
    ck_assert_str_eq(buffer, "");

    ret = safe_format_string(buffer, 8, "the %s %s dances away", "space", "man", NULL);
    ck_assert_int_eq(ret, 25);
    ck_assert_str_eq(buffer, "the spa");

    ret = safe_format_string(NULL, 0, "the %s %s dances away", "space", "man", NULL);
    ck_assert_int_eq(ret, 25);

    ret = safe_format_string(buffer, 8, "%5$s", NULL);
    ck_assert_int_lt(ret, 0);
}
END_TEST

static Suite *
create_safe_format_suite(void)
{
    Suite *s = suite_create("safe-format");
    TCase *tc_format = tcase_create("safe-format-string");

    /* One for each fixture */
    tcase_add_loop_test(tc_format, test_safe_format_string_cb, 0,
                        (sizeof (fixtures) / sizeof (fixtures[0])));

    tcase_add_test(tc_format, test_safe_format_string);

    suite_add_tcase(s, tc_format);

    return s;
}

int
main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int failure_count;
    Suite *suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        POPT_TABLEEND
    };

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

    suite = create_safe_format_suite();
    sr = srunner_create(suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
