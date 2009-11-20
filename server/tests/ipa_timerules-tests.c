/*
   Timelib

   test_timelib.c

   Copyright (C) Jakub Hrozek <jhrozek@redhat.com>        2009

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

#define _XOPEN_SOURCE /* strptime */

#include <check.h>
#include <popt.h>
#include <time.h>
#include <errno.h>
#include <stdlib.h>
#include <stdbool.h>

#include "providers/ipa/ipa_timerules.h"
#include "util/util.h"
#include "tests/common.h"

#define CHECK_TIME_RULE_LEAK(ctx, tctx, str, now, result) do { \
    check_leaks_push(ctx); \
    ret = check_time_rule(ctx, tctx, str, now, result); \
    check_leaks_pop(ctx); \
} while (0)

static TALLOC_CTX *ctx;

static void usage(poptContext pc, const char *error)
{
    poptPrintUsage(pc, stderr, 0);
    if (error) fprintf(stderr, "%s", error);
}

int str2time_t(const char *fmt, const char *str, time_t *out)
{
    char *err;
    struct tm stm;
    memset(&stm, 0, sizeof(struct tm));

    err = strptime(str, fmt, &stm);
    if(!err || err[0] != '\0')
        return EINVAL;

    DEBUG(9, ("after strptime: %s", asctime(&stm)));
    stm.tm_isdst = -1;
    *out = mktime(&stm);
    DEBUG(9, ("after mktime: %s", ctime(out)));
    return (*out == -1) ? EINVAL : EOK;
}

/* Fixtures - open the time library before every test, close it afterwards */
void setup(void)
{
    leak_check_setup();

    ctx = talloc_new(NULL);
    fail_if(ctx == NULL);
}

void teardown(void)
{
    leak_check_teardown();
}

/* Test that timelib detects a time rule inside the absolute range */
START_TEST(test_timelib_absolute_in_range)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;


    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%F", "2000-1-1", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 199412161032.5 ~ 200512161032,5", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error");

    talloc_free(tctx);
}
END_TEST

/* Test that timelib detects a time rule outside the absolute range */
START_TEST(test_timelib_absolute_out_of_range)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%F", "2007-1-1", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 199412161032.5 ~ 200512161032,5", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    talloc_free(tctx);
}
END_TEST

/* Test that absolute timeranges work OK with only minimal data supplied */
START_TEST(test_timelib_absolute_minimal)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%F", "2000-1-1", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 19941216 ~ 20051216", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error");

    talloc_free(tctx);
}
END_TEST

/* Test a time value "right off the edge" of the time specifier */
START_TEST(test_timelib_absolute_one_off)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M-%S", "1994-12-16-10-32-29", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 19941216103230 ~ 19941216103231", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M-%S", "1994-12-16-10-32-32", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 19941216103230 ~ 19941216103231", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    talloc_free(tctx);
}
END_TEST


/* Test a time value "right on the edge" of the time specifier */
START_TEST(test_timelib_absolute_one_on)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M-%S", "1994-12-16-10-32-30", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 19941216103230 ~ 19941216103231", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M-%S", "1994-12-16-10-32-31", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "absolute 19941216103230 ~ 19941216103231", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_daily_in)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error");

    /* test edges */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-09-30", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0930 ~ 1830", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == true, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-18-30", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0930 ~ 1830", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge2)");
    fail_unless(result == true, "Range check error");

    /* test wrap around */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-16-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == true, "Range check error1");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-15-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == true, "Range check error1");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-06-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == true, "Range check error1");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_daily_out)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-21-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    /* test one-off errors */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-09-29", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0930 ~ 1830", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (one-off 1)");
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-18-31", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 0930 ~ 1830", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (one-off 2)");
    fail_unless(result == false, "Range check error");

    /* test wrap around */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-10-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-14-59", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == false, "Range check error1");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-03-30-06-01", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic daily 1500 ~ 0600", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (edge1)");
    fail_unless(result == false, "Range check error2");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_weekly_in)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-02-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Mon-Fri 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error1");

    /* test edges - monday */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-22-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Mon-Fri 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error2");

    /* test edges - friday */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-26-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Mon-Fri 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error3");

    /* test wrap around */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-11-03-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Fri-Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error2");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-11-06-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Fri-Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == true, "Range check error3");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_weekly_out)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-04-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Mon-Fri 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    /* test one-off error - monday */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-22-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Tue-Thu 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    /* test one-off error - friday */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-26-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Tue-Thu 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error");

    /* test wrap around */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-11-04-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Fri-Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error2");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-11-05-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic weekly day Fri-Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule");
    fail_unless(result == false, "Range check error3");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_monthly_in)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-07-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 1,2 day Mon,Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule1 (ret = %d: %s)", ret, strerror(ret));
    fail_unless(result == true, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-05-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly day 1-5,10,15,20-25 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule2 (ret = %d: %s)", ret, strerror(ret));
    fail_unless(result == true, "Range check error");

    /* edges - week in */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-13-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 1,2 day Sat 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (week edge 1)");
    fail_unless(result == true, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-29-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 5 day Mon,Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (week edge 2)");
    fail_unless(result == true, "Range check error");

    /* edges - day in */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-01-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (day edge 1)");
    fail_unless(result == true, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-10-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (day edge 2)");
    fail_unless(result == true, "Range check error");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_monthly_out)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-03-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 1,2 day Mon,Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (ret = %d)", ret);
    fail_unless(result == false, "Range check error");

    /* one-off error - week out */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-15-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 1 day Sun-Sat 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (week edge 1)");
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-28-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly week 5 day Mon,Tue 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (week edge 2)");
    fail_unless(result == false, "Range check error");

    /* one-off error - day out */
    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-01-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly day 2-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (day edge 1)");
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-04-11-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic monthly day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (day edge 2)");
    fail_unless(result == false, "Range check error");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_yearly_in)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-08-03-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 1,7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (ret = %d)", ret);
    fail_unless(result == true, "Range check error1");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-01-01-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 1,7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (ret = %d)", ret);
    fail_unless(result == true, "Range check error2");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-01-01-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly week 1 day 1-7 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (ret = %d)", ret);
    fail_unless(result == true, "Range check error3");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-07-10-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 1,7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule (ret = %d)", ret);
    fail_unless(result == true, "Range check error4");

    talloc_free(tctx);
}
END_TEST

START_TEST(test_timelib_periodic_yearly_out)
{
    time_t now;
    int ret;
    bool result;
    static struct time_rules_ctx *tctx = NULL;

    ret = init_time_rules_parser(ctx, &tctx);
    fail_if(ret != EOK);

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-06-13-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule1 (ret = %d)", ret);
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-09-13-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule2 (ret = %d)", ret);
    fail_unless(result == false, "Range check error");

    fail_unless(str2time_t("%Y-%m-%d-%H-%M", "2009-01-11-12-00", &now) == 0, "Cannot parse time spec");
    CHECK_TIME_RULE_LEAK(ctx, tctx, "periodic yearly month 1,7-8 day 1-10 0900 ~ 1800", now, &result);
    fail_unless(ret == EOK, "Fail to check the time rule3 (ret = %d)", ret);
    fail_unless(result == false, "Range check error");

    talloc_free(tctx);
}
END_TEST

Suite *create_timelib_suite(void)
{
    Suite *s = suite_create("timelib");

    TCase *tc_timelib = tcase_create("Timelib Tests");


    /* Add setup() and teardown() methods */
    tcase_add_checked_fixture(tc_timelib, setup, teardown);

    /* Do some testing */
    tcase_add_test(tc_timelib, test_timelib_absolute_in_range);
    tcase_add_test(tc_timelib, test_timelib_absolute_out_of_range);
    tcase_add_test(tc_timelib, test_timelib_absolute_minimal);
    tcase_add_test(tc_timelib, test_timelib_absolute_one_off);
    tcase_add_test(tc_timelib, test_timelib_absolute_one_on);

    tcase_add_test(tc_timelib, test_timelib_periodic_daily_in);
    tcase_add_test(tc_timelib, test_timelib_periodic_daily_out);
    tcase_add_test(tc_timelib, test_timelib_periodic_weekly_in);
    tcase_add_test(tc_timelib, test_timelib_periodic_weekly_out);
    tcase_add_test(tc_timelib, test_timelib_periodic_monthly_in);
    tcase_add_test(tc_timelib, test_timelib_periodic_monthly_out);
    tcase_add_test(tc_timelib, test_timelib_periodic_yearly_in);
    tcase_add_test(tc_timelib, test_timelib_periodic_yearly_out);

    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc_timelib);

    return s;
}

int main(int argc, const char *argv[])
{
    int ret;
    poptContext pc;
    int failure_count;
    Suite *timelib_suite;
    SRunner *sr;
    int debug = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug, 0, "Set debug level", NULL },
        POPT_TABLEEND
    };

    pc = poptGetContext(NULL, argc, (const char **) argv, long_options, 0);
    if((ret = poptGetNextOpt(pc)) < -1) {
        usage(pc, poptStrerror(ret));
        return EXIT_FAILURE;
    }
    debug_level = debug;

    timelib_suite = create_timelib_suite();
    sr = srunner_create(timelib_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}

