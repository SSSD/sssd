/*
   SSSD

   IPA Provider Time Rules Parsing

   Authors:
        Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2009

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

#define _XOPEN_SOURCE /* strptime() needs this */

#include <pcre.h>
#include <talloc.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <time.h>
#include <stdbool.h>
#include <limits.h>

#include "providers/ipa/ipa_timerules.h"
#include "util/util.h"

#define JMP_NEOK(variable) do {     \
    if (variable != EOK) goto done; \
} while (0)

#define JMP_NEOK_LABEL(variable, label) do {     \
    if (variable != EOK) goto label;             \
} while (0)

#define CHECK_PTR(ptr)  do {        \
    if (ptr == NULL) {              \
        return ENOMEM;              \
    }                               \
} while (0)

#define CHECK_PTR_JMP(ptr)  do {    \
    if (ptr == NULL) {              \
        ret = ENOMEM;               \
        goto done;                  \
    }                               \
} while (0)

#define BUFFER_OR_JUMP(ctx, ptr, count) do {        \
    ptr = talloc_array(ctx, unsigned char, count);  \
    if (ptr == NULL) {                              \
        return ENOMEM;                              \
    }                                               \
    memset(ptr, 0, sizeof(unsigned char)*count);    \
} while (0)

#define TEST_BIT_RANGE(bitfield, index, resptr) do {  \
    if (bitfield) {                                   \
        if (test_bit(&bitfield, index) == 0) {        \
            *resptr = false;                          \
            return EOK;                               \
        }                                             \
    }                                                 \
} while (0)

#define TEST_BIT_RANGE_PTR(bitfield, index, resptr) do {    \
    if (bitfield) {                                         \
        if (test_bit(bitfield, index) == 0) {               \
            *resptr = false;                                \
            return EOK;                                     \
        }                                                   \
    }                                                       \
} while (0)

/* number of match offsets when matching pcre regexes */
#define OVEC_SIZE   30

/* regular expressions describing syntax of our HBAC grammar */
#define RGX_WEEKLY      "day (?P<day_of_week>(0|1|2|3|4|5|6|7|Mon|Tue|Wed|Thu|Fri|Sat|Sun|,|-)+)"

#define RGX_MDAY        "(?P<mperspec_day>day) (?P<interval_day>[0-9,-]+) "
#define RGX_MWEEK       "(?P<mperspec_week>week) (?P<interval_week>[0-9,-]+) "RGX_WEEKLY
#define RGX_MONTHLY     RGX_MDAY"|"RGX_MWEEK

#define RGX_YDAY        "(?P<yperspec_day>day) (?P<day_of_year>[0-9,-]+) "
#define RGX_YWEEK       "(?P<yperspec_week>week) (?P<week_of_year>[0-9,-]+) "RGX_WEEKLY
#define RGX_YMONTH      "(?P<yperspec_month>month) (?P<month_number>[0-9,-]+) (?P<m_period>.*?)$"
#define RGX_YEARLY      RGX_YMONTH"|"RGX_YWEEK"|"RGX_YDAY

#define RGX_TIMESPEC    "(?P<timeFrom>[0-9]{4}) ~ (?P<timeTo>[0-9]{4})"

#define RGX_GENERALIZED "(?P<year>[0-9]{4})(?P<month>[0-9]{2})(?P<day>[0-9]{2})(?P<hour>[0-9]{2})?(?P<minute>[0-9]{2})?(?P<second>[0-9]{2})?"

#define RGX_PERIODIC    "^periodic (?P<perspec>daily|weekly|monthly|yearly) (?P<period>.*?)"RGX_TIMESPEC"$"
#define RGX_ABSOLUTE    "^absolute (?P<from>\\S+) ~ (?P<to>\\S+)$"

/* limits on various parameters */
#define DAY_OF_WEEK_MAX     7
#define DAY_OF_MONTH_MAX    31
#define WEEK_OF_MONTH_MAX   5
#define WEEK_OF_YEAR_MAX    54
#define DAY_OF_YEAR_MAX     366
#define MONTH_MAX           12
#define HOUR_MAX            23
#define MINUTE_MAX          59

/* limits on sizes of buffers for bit arrays */
#define DAY_OF_MONTH_BUFSIZE    8
#define DAY_OF_YEAR_BUFSIZE     44
#define WEEK_OF_YEAR_BUFSIZE    13
#define MONTH_BUFSIZE           2
#define HOUR_BUFSIZE            4
#define MINUTE_BUFSIZE          8

/* Lookup tables for translating names of days and months */
static const char *names_day_of_week[] =
            { "Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun", NULL };
static const char *names_months[] =
            { "Jan", "Feb", "Mar", "Apr", "May", "Jun",
              "Jul", "Aug", "Sep", "Nov", "Dec", NULL };

/*
 * Timelib knows two types of ranges - periodic and absolute
 */
enum rangetypes {
    TYPE_ABSOLUTE,
    TYPE_PERIODIC
};

struct absolute_range {
    time_t time_from;
    time_t time_to;
};

struct periodic_range {
    unsigned char day_of_week;
    unsigned char *day_of_month;
    unsigned char *day_of_year;
    unsigned char week_of_month;
    unsigned char *week_of_year;
    unsigned char *month;
    unsigned char *hour;
    unsigned char *minute;
};

/*
 * Context of one time rule being analyzed
 */
struct range_ctx {
    /* main context with precompiled patterns */
    struct time_rules_ctx *trctx;
    /* enum rangetypes */
    enum rangetypes type;

    struct absolute_range *abs;
    struct periodic_range *per;
};


/*
 * The context of one regular expression
 */
struct parse_ctx {
    /* the regular expression used for one parsing */
    pcre    *re;
    /* number of matches */
    int     matches;
    /* vector of matches */
    int     *ovec;
};

/* indexes to the array of precompiled regexes */
enum timelib_rgx {
    LP_RGX_GENERALIZED,
    LP_RGX_MDAY,
    LP_RGX_MWEEK,
    LP_RGX_YEARLY,
    LP_RGX_WEEKLY,
    LP_RGX_ABSOLUTE,
    LP_RGX_PERIODIC,
    LP_RGX_MAX,
};

/* matches the indexes */
static const char *lookup_table[] = {
    RGX_GENERALIZED,
    RGX_MDAY,
    RGX_MWEEK,
    RGX_YEARLY,
    RGX_WEEKLY,
    RGX_ABSOLUTE,
    RGX_PERIODIC,
    NULL,
};

/*
 * Main struct passed outside
 * holds precompiled regular expressions
 */
struct time_rules_ctx {
    pcre *re[LP_RGX_MAX];
};

/*******************************************************************
 * helper function - bit arrays                                    *
 *******************************************************************/

/* set a single bit in a bitmap */
static void set_bit(unsigned char *bitmap, unsigned int bit)
{
    bitmap[bit/CHAR_BIT] |= 1 << (bit%CHAR_BIT);
}

/*
 * This function is based on bit_nset macro written originally by Paul Vixie,
 * copyrighted by The Regents of the University of California, as found
 * in tarball of fcron, file bitstring.h
 */
static void set_bit_range(unsigned char *bitmap, unsigned int start,
                          unsigned int stop)
{
    int startbyte = start/CHAR_BIT;
    int stopbyte = stop/CHAR_BIT;

    if (startbyte == stopbyte) {
        bitmap[startbyte] |= ((0xff << (start & 0x7)) &
                             (0xff >> (CHAR_BIT- 1 - (stop & 0x7))));
    } else {
        bitmap[startbyte] |= 0xff << (start & 0x7);
        while (++startbyte < stopbyte) {
            bitmap[startbyte] |= 0xff;
        }
        bitmap[stopbyte] |= 0xff >>  (CHAR_BIT- 1 - (stop & 0x7));
    }
}

static int test_bit(unsigned char *bitmap, unsigned int bit)
{
    return (int)(bitmap[bit/CHAR_BIT] >> (bit%CHAR_BIT)) & 1;
}

/*******************************************************************
 * parsing intervals                                               *
 *******************************************************************/

/*
 * Some ranges allow symbolic names, like Mon..Sun for names of day.
 * This routine takes a list of symbolic names as NAME_ARRAY and the
 * one we're looking for as KEY and returns its index or -1 when not
 * found. The last member of NAME_ARRAY must be NULL.
 */
static int name_index(const char **name_array, const char *key, int min)
{
    int index = 0;
    const char *one;

    if (name_array == NULL) {
        return -1;
    }

    while ((one = name_array[index]) != NULL) {
        if (strcmp(key,one) == 0) {
            return index+min;
        }
        index++;
    }

    return -1;
}

/*
 * Sets appropriate bits given by an interval in STR (in form of 1,5-7,10) to
 * a bitfield given in OUT. Does no boundary checking. STR can also contain
 * symbolic names, these would be given in TRANSLATE.
 */
static int interval2bitfield(TALLOC_CTX *mem_ctx,
                             unsigned char *out,
                             const char *str,
                             int min, int max,
                             const char **translate)
{
    char *copy;
    char *next, *token;
    int tokval, tokmax;
    char *end_ptr;
    int ret;
    char *dash;

    DEBUG(9, ("Converting '%s' to interval\n", str));

    copy = talloc_strdup(mem_ctx, str);
    CHECK_PTR(copy);

    next = copy;
    while (next) {
        token = next;
        next = strchr(next, ',');
        if (next) {
            *next = '\0';
            next++;
        }

        errno = 0;
        tokval = strtol(token, &end_ptr, 10);
        if (*end_ptr == '\0' && errno == 0) {
            if (tokval <= max && tokval >= 0) {
                set_bit(out, tokval);
                continue;
            } else {
                ret = ERANGE;
                goto done;
            }
        } else if ((dash = strchr(token, '-')) != NULL){
            *dash = '\0';
            ++dash;

            errno = 0;
            tokval = strtol(token, &end_ptr, 10);
            if (*end_ptr != '\0' || errno != 0) {
                tokval = name_index(translate, token, min);
                if (tokval == -1) {
                    ret = ERANGE;
                    goto done;
                }
            }
            errno = 0;
            tokmax = strtol(dash, &end_ptr, 10);
            if (*end_ptr != '\0' || errno != 0) {
                tokmax = name_index(translate, dash, min);
                if (tokmax == -1) {
                    ret = ERANGE;
                    goto done;
                }
            }

            if (tokval <= max && tokmax <= max &&
                tokval >= min && tokmax >= min) {
                if (tokmax > tokval) {
                    DEBUG(7, ("Setting interval %d-%d\n", tokval, tokmax));
                    DEBUG(9, ("interval: %p\n", out));
                    set_bit_range(out, tokval, tokmax);
                } else {
                    /* Interval wraps around - i.e. from 18.00 to 06.00 */
                    DEBUG(7, ("Setting inverted interval %d-%d\n", tokval, tokmax));
                    DEBUG(9, ("interval: %p\n", out));
                    set_bit_range(out, min, tokmax);
                    set_bit_range(out, tokval, max);
                }
                continue;
            } else {
                /* tokval or tokmax are not between <min, max> */
                ret = ERANGE;
                goto done;
            }
        } else if ((tokval = name_index(translate, token, min)) != -1) {
            /* Try to translate one token by name */
            if (tokval <= max) {
                set_bit(out, tokval);
                continue;
            } else {
                ret = ERANGE;
                goto done;
            }
        } else {
                ret = EINVAL;
                goto done;
        }
    }

    ret = EOK;
done:
    talloc_free(copy);
    return ret;
}

/*******************************************************************
 * wrappers around regexp handling                                 *
 *******************************************************************/

/*
 * Copies a named substring SUBSTR_NAME from string STR using the parsing
 * information from PCTX. The context PCTX is also used as a talloc context.
 *
 * The resulting string is stored in OUT.
 * Return value is EOK on no error or ENOENT on error capturing the substring
 */
static int copy_substring(struct parse_ctx *pctx,
                          const char *str,
                          const char *substr_name,
                          char **out)
{
    const char *result = NULL;
    int ret;
    char *o = NULL;

    result = NULL;

    ret = pcre_get_named_substring(pctx->re, str, pctx->ovec,
                                   pctx->matches, substr_name, &result);
    if (ret < 0  || result == NULL) {
        DEBUG(5, ("named substring '%s' does not exist in '%s'\n",
                  substr_name, str));
        return ENOENT;
    }

    o = talloc_strdup(pctx, result);
    pcre_free_substring(result);
    if (o == NULL) {
        return ENOMEM;
    }

    DEBUG(9, ("Copied substring named '%s' value '%s'\n", substr_name, o));

    *out = o;
    return EOK;
}

/*
 * Copies a named substring SUBSTR_NAME from string STR using the parsing
 * information from PCTX and converts it to an integer.
 * The context PCTX is also used as a talloc context.
 *
 * The resulting string is stored in OUT.
 * Return value is EOK on no error or ENOENT on error capturing the substring
 */
static int substring_strtol(struct parse_ctx *pctx,
                            const char *str,
                            const char *substr_name,
                            int *out)
{
    char *substr = NULL;
    int ret;
    int val;
    char *err_ptr;

    ret = copy_substring(pctx, str, substr_name, &substr);
    if (ret != EOK) {
        DEBUG(5, ("substring '%s' does not exist\n", substr_name));
        return ret;
    }

    errno = 0;
    val = strtol(substr, &err_ptr, 10);
    if (substr == '\0' || *err_ptr != '\0' || errno != 0) {
        DEBUG(5, ("substring '%s' does not contain an integerexist\n",
                  substr));
        talloc_free(substr);
        return EINVAL;
    }

    *out = val;
    talloc_free(substr);
    return EOK;
}

/*
 * Compiles a regular expression REGEXP and tries to match it against the
 * string STR. Fills in structure _PCTX with info about matching.
 *
 * Returns EOK on no error, EFAULT on bad regexp, EINVAL when it cannot
 * match the regexp.
 */
static int matches_regexp(TALLOC_CTX *ctx,
                          struct time_rules_ctx *trctx,
                          const char *str,
                          enum timelib_rgx regex,
                          struct parse_ctx **_pctx)
{
    int ret;
    struct parse_ctx *pctx = NULL;

    pctx = talloc_zero(ctx, struct parse_ctx);
    CHECK_PTR(pctx);
    pctx->ovec = talloc_array(pctx, int, OVEC_SIZE);
    CHECK_PTR_JMP(pctx->ovec);
    pctx->re = trctx->re[regex];

    ret = pcre_exec(pctx->re, NULL, str, strlen(str), 0, PCRE_NOTEMPTY, pctx->ovec, OVEC_SIZE);
    if (ret <= 0) {
        DEBUG(8, ("string '%s' did *NOT* match regexp '%s'\n", str, lookup_table[regex]));
        ret = EINVAL;
        goto done;
    }
    DEBUG(8, ("string '%s' matched regexp '%s'\n", str, lookup_table[regex]));

    pctx->matches = ret;
    *_pctx = pctx;
    return EOK;

done:
    talloc_free(pctx);
    return ret;
}

/*******************************************************************
 * date/time helper functions                                      *
 *******************************************************************/

/*
 * Returns week number as an integer
 * This may seem ugly, but I think it's actually less error prone
 * than writing my own routine
 */
static int weeknum(const struct tm *t)
{
    char buf[3];

    if (!strftime(buf, 3, "%U", t)) {
        return -1;
    }

    /* %U returns 0-53, we want 1-54 */
    return atoi(buf)+1;
}

/*
 * Return the week of the month
 * Range is 1 to 5
 */
static int get_week_of_month(const struct tm *t)
{
    int fs;                       /* first sunday */

    fs = (t->tm_mday % 7) - t->tm_wday;
    if (fs <= 0) {
        fs += 7;
    }

    return (t->tm_mday <= fs) ? 1 : (2 + (t->tm_mday - fs - 1) / 7);
}

/*
 * Normalize differencies between our HBAC definition and semantics of
 * struct tm
 */
static void abs2tm(struct tm *t)
{
    /* tm defines tm_year as num of yrs since 1900, we have absolute number */
    t->tm_year %= 1900;
    /* struct tm defines tm_mon as number of month since January */
    t->tm_mon--;
}

/*
 * Normalize differencies between our HBAC definition and semantics of
 * struct tm
 */
static void tm2abs(struct tm *t)
{
    /* tm defines tm_year as num of yrs since 1900, we have absolute number */
    t->tm_year += 1900;
    /* struct tm defines  tm_mon as number of month since January */
    t->tm_mon++;
}

/*******************************************************************
 * parsing of HBAC rules themselves                                *
 *******************************************************************/

/*
 * Parses generalized time string given in STR and fills the
 * information into OUT.
 */
static int parse_generalized_time(struct parse_ctx *pctx,
                                  struct time_rules_ctx *trctx,
                                  const char *str,
                                  time_t *out)
{
    int     ret;
    struct  parse_ctx *gctx = NULL;
    struct tm tm;

    memset(&tm, 0, sizeof(tm));
    tm.tm_isdst = -1;

    ret = matches_regexp(pctx, trctx, str, LP_RGX_GENERALIZED, &gctx);
    JMP_NEOK(ret);

    /* compulsory */
    ret = substring_strtol(gctx, str, "year", &tm.tm_year);
    JMP_NEOK(ret);
    ret = substring_strtol(gctx, str, "month", &tm.tm_mon);
    JMP_NEOK(ret);
    ret = substring_strtol(gctx, str, "day", &tm.tm_mday);
    JMP_NEOK(ret);
    /* optional */
    ret = substring_strtol(gctx, str, "hour", &tm.tm_hour);
    JMP_NEOK_LABEL(ret, enoent);
    ret = substring_strtol(gctx, str, "minute", &tm.tm_min);
    JMP_NEOK_LABEL(ret, enoent);
    ret = substring_strtol(gctx, str, "second", &tm.tm_sec);
    JMP_NEOK_LABEL(ret, enoent);

enoent:
    if (ret == ENOENT) {
        ret = EOK;
    }

    abs2tm(&tm);

    *out = mktime(&tm);
    DEBUG(3, ("converted to time: '%s'\n", ctime(out)));
    if (*out == -1) {
        ret = EINVAL;
    }
done:
    talloc_free(gctx);
    return ret;
}

/*
 * Parses absolute timerange string given in STR and fills the
 * information into ABS.
 */
static int parse_absolute(struct absolute_range *absr,
                          struct time_rules_ctx *trctx,
                          struct parse_ctx *pctx,
                          const char *str)
{
    char *from = NULL, *to = NULL;
    int ret;

    ret = copy_substring(pctx, str, "from", &from);
    if (ret != EOK) {
        DEBUG(1, ("Missing required part 'from' in absolute timespec\n"));
        ret = EINVAL;
        goto done;
    }
    ret = copy_substring(pctx, str, "to", &to);
    if (ret != EOK) {
        DEBUG(1, ("Missing required part 'to' in absolute timespec\n"));
        ret = EINVAL;
        goto done;
    }

    ret = parse_generalized_time(pctx, trctx, from, &absr->time_from);
    if (ret != EOK) {
        DEBUG(1, ("Cannot parse generalized time - first part\n"));
        goto done;
    }

    ret = parse_generalized_time(pctx, trctx, to, &absr->time_to);
    if (ret != EOK) {
        DEBUG(1, ("Cannot parse generalized time - second part\n"));
        goto done;
    }

    if (difftime(absr->time_to, absr->time_from) < 0) {
        DEBUG(1, ("Not a valid interval\n"));
        ret = EINVAL;
    }

    ret = EOK;
done:
    talloc_free(from);
    talloc_free(to);
    return ret;
}

static int parse_hhmm(const char *str, int *hour, int *min)
{
    struct tm t;
    char *err;

    err = strptime(str, "%H%M", &t);
    if (*err != '\0') {
        return EINVAL;
    }

    *hour = t.tm_hour;
    *min  = t.tm_min;

    return EOK;
}

/*
 * Parses monthly periodic timerange given in STR.
 * Fills the information into PER.
 */
static int parse_periodic_monthly(TALLOC_CTX *ctx,
                                  struct time_rules_ctx *trctx,
                                  struct periodic_range *per,
                                  const char *str)
{
    int ret;
    struct parse_ctx *mpctx = NULL;
    char *match = NULL;
    char *mperspec = NULL;

    /* This code would be much less ugly if RHEL5 PCRE knew about PCRE_DUPNAMES */
    ret = matches_regexp(ctx, trctx, str, LP_RGX_MDAY, &mpctx);
    if (ret == EOK) {
        ret = copy_substring(mpctx, str, "mperspec_day", &mperspec);
        JMP_NEOK(ret);
        ret = copy_substring(mpctx, str, "interval_day", &match);
        JMP_NEOK(ret);
        BUFFER_OR_JUMP(per, per->day_of_month, DAY_OF_MONTH_BUFSIZE);
        ret = interval2bitfield(mpctx, per->day_of_month, match,
                                1, DAY_OF_MONTH_MAX, NULL);
        JMP_NEOK(ret);
    } else {
        ret = matches_regexp(ctx, trctx, str, LP_RGX_MWEEK, &mpctx);
        JMP_NEOK(ret);
        ret = copy_substring(mpctx, str, "mperspec_week", &mperspec);
        JMP_NEOK(ret);

        ret = copy_substring(mpctx, str, "interval_week", &match);
        JMP_NEOK(ret);
        ret = interval2bitfield(mpctx, &per->week_of_month, match,
                                1, WEEK_OF_MONTH_MAX, NULL);
        JMP_NEOK(ret);

        ret = copy_substring(mpctx, str, "day_of_week", &match);
        JMP_NEOK(ret);
        ret = interval2bitfield(mpctx, &per->day_of_week, match,
                                1, DAY_OF_WEEK_MAX, names_day_of_week);
        JMP_NEOK(ret);
    }

done:
    talloc_free(mpctx);
    return ret;
}

/*
 * Parses yearly periodic timerange given in STR.
 * Fills the information into PER.
 */
static int parse_periodic_yearly(TALLOC_CTX *ctx,
                                 struct time_rules_ctx *trctx,
                                 struct periodic_range *per,
                                 const char *str)
{
    int ret;
    struct parse_ctx *ypctx = NULL;
    char *match = NULL;
    char *yperspec = NULL;

    ret = matches_regexp(ctx, trctx, str, LP_RGX_YEARLY, &ypctx);
    JMP_NEOK(ret);
    ret = copy_substring(ypctx, str, "yperspec_day", &yperspec);
    if (ret == EOK) {
        ret = copy_substring(ypctx, str, "day_of_year", &match);
        JMP_NEOK(ret);
        BUFFER_OR_JUMP(per, per->day_of_year, DAY_OF_YEAR_BUFSIZE);
        ret = interval2bitfield(ypctx, per->day_of_year, match,
                                1, DAY_OF_YEAR_MAX, NULL);
        JMP_NEOK(ret);
    }

    if (ret != ENOENT) goto done;

    ret = copy_substring(ypctx, str, "yperspec_week", &yperspec);
    if (ret == EOK) {
        ret = copy_substring(ypctx, str, "week_of_year", &match);
        JMP_NEOK(ret);
        BUFFER_OR_JUMP(per, per->week_of_year, WEEK_OF_YEAR_BUFSIZE);
        ret = interval2bitfield(ypctx, per->week_of_year, match,
                                1, WEEK_OF_YEAR_MAX, NULL);
        JMP_NEOK(ret);

        talloc_free(match);
        ret = copy_substring(ypctx, str, "day_of_week", &match);
        JMP_NEOK(ret);
        ret = interval2bitfield(ypctx, &per->day_of_week, match,
                                1, DAY_OF_WEEK_MAX, names_day_of_week);
        JMP_NEOK(ret);
    }

    if (ret != ENOENT) goto done;

    ret = copy_substring(ypctx, str, "yperspec_month", &yperspec);
    JMP_NEOK(ret);

    talloc_free(match);
    ret = copy_substring(ypctx, str, "month_number", &match);
    JMP_NEOK(ret);
    BUFFER_OR_JUMP(per, per->month, MONTH_BUFSIZE);
    ret = interval2bitfield(ypctx, per->month, match,
                            1, MONTH_MAX, names_months);
    JMP_NEOK(ret);

    talloc_free(match);
    ret = copy_substring(ypctx, str, "m_period", &match);
    JMP_NEOK(ret);
    DEBUG(7, ("Monthly year period - calling parse_periodic_monthly()\n"));
    ret = parse_periodic_monthly(ypctx, trctx, per, match);
    JMP_NEOK(ret);

done:
    talloc_free(ypctx);
    return ret;
}

/*
 * Parses weekly periodic timerange given in STR.
 * Fills the information into PER.
 */
static int parse_periodic_weekly(TALLOC_CTX *ctx,
                                 struct time_rules_ctx *trctx,
                                 struct periodic_range *per,
                                 const char *str)
{
    int ret;
    struct parse_ctx *wpctx = NULL;
    char *dow = NULL;

    ret = matches_regexp(ctx, trctx, str, LP_RGX_WEEKLY, &wpctx);
    JMP_NEOK(ret);

    ret = copy_substring(wpctx, str, "day_of_week", &dow);
    JMP_NEOK(ret);
    DEBUG(8, ("day_of_week = '%s'\n", dow));

    ret = interval2bitfield(wpctx, &per->day_of_week, dow,
                            1, DAY_OF_WEEK_MAX, names_day_of_week);

done:
    talloc_free(wpctx);
    return ret;
}

static int parse_periodic_time(struct periodic_range *per,
                               struct parse_ctx *pctx,
                               const char *str)
{
    char *substr = NULL;
    int ret;

    int hour_from;
    int hour_to;
    int min_from;
    int min_to;

    /* parse out the time */
    ret = copy_substring(pctx, str, "timeFrom", &substr);
    JMP_NEOK(ret);
    parse_hhmm(substr, &hour_from, &min_from);
    DEBUG(7, ("Parsed timeFrom: %d:%d\n", hour_from, min_from));
    JMP_NEOK(ret);

    talloc_free(substr);
    ret = copy_substring(pctx, str, "timeTo", &substr);
    JMP_NEOK(ret);
    parse_hhmm(substr, &hour_to, &min_to);
    DEBUG(7, ("Parsed timeTo: %d:%d\n", hour_to, min_to));
    JMP_NEOK(ret);

    /* set the interval */
    if (hour_from > hour_to ) {
        set_bit_range(per->hour, 0, hour_to);
        set_bit_range(per->hour, hour_from, HOUR_MAX);
    } else {
        set_bit_range(per->hour, hour_from, hour_to);
    }

    if (min_from > min_to) {
        set_bit_range(per->minute, 0, min_to);
        set_bit_range(per->minute, min_from, MINUTE_MAX);
    } else {
        set_bit_range(per->minute, min_from, min_to);
    }


    ret = EOK;
done:
    talloc_free(substr);
    return ret;
}

/*
 * Parses periodic timerange given in STR.
 * Fills the information into PER.
 */
static int parse_periodic(struct periodic_range *per,
                          struct time_rules_ctx *trctx,
                          struct parse_ctx *pctx,
                          const char *str)
{
    char *substr = NULL;
    char *period = NULL;
    int ret;

    /* These are mandatory */
    BUFFER_OR_JUMP(per, per->hour, HOUR_BUFSIZE);
    BUFFER_OR_JUMP(per, per->minute, MINUTE_BUFSIZE);

    ret = copy_substring(pctx, str, "perspec", &substr);
    JMP_NEOK(ret);
    ret = copy_substring(pctx, str, "period", &period);
    JMP_NEOK(ret);

    if (strcmp(substr, "yearly") == 0) {
        DEBUG(5, ("periodic yearly\n"));
        ret = parse_periodic_yearly(pctx, trctx, per, period);
        JMP_NEOK(ret);
    } else if (strcmp(substr, "monthly") == 0) {
        DEBUG(5, ("periodic monthly\n"));
        ret = parse_periodic_monthly(pctx, trctx, per, period);
        JMP_NEOK(ret);
    } else if (strcmp(substr, "weekly") == 0) {
        DEBUG(5, ("periodic weekly\n"));
        ret = parse_periodic_weekly(pctx, trctx, per, period);
        JMP_NEOK(ret);
    } else if (strcmp(substr, "daily") == 0) {
        DEBUG(5, ("periodic daily\n"));
    } else {
        DEBUG(1, ("Cannot determine periodic rule type"
                  "(perspec = '%s', period = '%s')\n", substr, period));
        ret = EINVAL;
        goto done;
    }

    talloc_free(period);

    ret = parse_periodic_time(per, pctx, str);
    JMP_NEOK(ret);

    ret = EOK;
done:
    talloc_free(substr);
    return ret;
}

/*
 * Parses time specification given in string RULE into range_ctx
 * context CTX.
 */
static int parse_timespec(struct range_ctx *ctx, const char *rule)
{
    int ret;
    struct parse_ctx *pctx = NULL;

    if (matches_regexp(ctx, ctx->trctx, rule, LP_RGX_ABSOLUTE, &pctx) == EOK) {
        DEBUG(5, ("Matched absolute range\n"));
        ctx->type = TYPE_ABSOLUTE;
        ctx->abs = talloc_zero(ctx, struct absolute_range);
        CHECK_PTR_JMP(ctx->abs);

        ret = parse_absolute(ctx->abs, ctx->trctx, pctx, rule);
        JMP_NEOK(ret);
    } else if (matches_regexp(ctx, ctx->trctx, rule, LP_RGX_PERIODIC, &pctx) == EOK) {
        DEBUG(5, ("Matched periodic range\n"));
        ctx->type = TYPE_PERIODIC;
        ctx->per = talloc_zero(ctx, struct periodic_range);
        CHECK_PTR_JMP(ctx->per);

        ret = parse_periodic(ctx->per, ctx->trctx, pctx, rule);
        JMP_NEOK(ret);
    } else {
        DEBUG(1, ("Cannot determine rule type\n"));
        ret = EINVAL;
        goto done;
    }

    ret = EOK;
done:
    talloc_free(pctx);
    return ret;
}

/*******************************************************************
 * validation of rules against time_t                              *
 *******************************************************************/

static int absolute_timerange_valid(struct absolute_range *absr,
                                    const time_t now,
                                    bool *result)
{
    if (difftime(absr->time_from, now) > 0) {
        DEBUG(3, ("Absolute timerange invalid (before interval)\n"));
        *result = false;
        return EOK;
    }

    if (difftime(absr->time_to, now) < 0) {
        DEBUG(3, ("Absolute timerange invalid (after interval)\n"));
        *result = false;
        return EOK;
    }

    DEBUG(3, ("Absolute timerange valid\n"));
    *result = true;
    return EOK;
}

static int periodic_timerange_valid(struct periodic_range *per,
                                    const time_t now,
                                    bool *result)
{
    struct tm tm_now;
    int wnum;
    int wom;

    memset(&tm_now, 0, sizeof(struct tm));
    if (localtime_r(&now, &tm_now) == NULL) {
        DEBUG(0, ("Cannot convert time_t to struct tm\n"));
        return EFAULT;
    }
    DEBUG(9, ("Got struct tm value %s", asctime(&tm_now)));
    tm2abs(&tm_now);

    wnum = weeknum(&tm_now);
    if (wnum == -1) {
        DEBUG(7, ("Cannot get week number"));
        return EINVAL;
    }
    DEBUG(9, ("Week number is %d\n", wnum));

    wom = get_week_of_month(&tm_now);
    if (wnum == -1) {
        DEBUG(7, ("Cannot get week of number"));
        return EINVAL;
    }
    DEBUG(9, ("Week of month number is %d\n", wom));

    /* The validation itself */
    TEST_BIT_RANGE(per->day_of_week, tm_now.tm_wday, result);
    DEBUG(9, ("day of week OK\n"));
    TEST_BIT_RANGE_PTR(per->day_of_month, tm_now.tm_mday, result);
    DEBUG(9, ("day of month OK\n"));
    TEST_BIT_RANGE(per->week_of_month, wom, result);
    DEBUG(9, ("week of month OK\n"));
    TEST_BIT_RANGE_PTR(per->week_of_year, wnum, result);
    DEBUG(9, ("week of year OK\n"));
    TEST_BIT_RANGE_PTR(per->month, tm_now.tm_mon, result);
    DEBUG(9, ("month OK\n"));
    TEST_BIT_RANGE_PTR(per->day_of_year, tm_now.tm_yday, result);
    DEBUG(9, ("day of year OK\n"));
    TEST_BIT_RANGE_PTR(per->hour, tm_now.tm_hour, result);
    DEBUG(9, ("hour OK\n"));
    TEST_BIT_RANGE_PTR(per->minute, tm_now.tm_min, result);
    DEBUG(9, ("minute OK\n"));

    DEBUG(3, ("Periodic timerange valid\n"));
    *result = true;
    return EOK;
}

/*
 * Returns EOK if the timerange in range_ctx context is valid compared against a
 * given time_t value in NOW, returns ERANGE if the time value is outside the
 * specified range.
 */
static int timerange_valid(struct range_ctx *ctx,
                           const time_t now,
                           bool *result)
{
    int ret;

    switch(ctx->type) {
        case TYPE_ABSOLUTE:
            DEBUG(7, ("Checking absolute range\n"));
            ret = absolute_timerange_valid(ctx->abs, now, result);
            break;

        case TYPE_PERIODIC:
            DEBUG(7, ("Checking periodic range\n"));
            ret = periodic_timerange_valid(ctx->per, now, result);
            break;

        default:
            DEBUG(1, ("Unknown range type (%d)\n", ctx->type));
            ret = EINVAL;
            break;
    }

    return ret;
}

/*******************************************************************
 * public interface                                                *
 *******************************************************************/

/*
 * This is actually the meat of the library. The function takes a string
 * representation of a time rule in STR and time to check against (usually that
 * would be current time) in NOW.
 *
 * It returns EOK if the rule is valid in the current time, ERANGE if not and
 * EINVAL if the rule cannot be parsed
 */
int check_time_rule(TALLOC_CTX *mem_ctx,
                    struct time_rules_ctx *trctx,
                    const char *str,
                    const time_t now,
                    bool *result)
{
    int ret;
    struct range_ctx *ctx;

    ctx = talloc_zero(mem_ctx, struct range_ctx);
    CHECK_PTR_JMP(ctx);
    ctx->trctx = trctx;

    DEBUG(9, ("Got time_t value %s", ctime(&now)));

    ret = parse_timespec(ctx, str);
    if (ret != EOK) {
        DEBUG(1, ("Cannot parse the time specification (%d)\n", ret));
        goto done;
    }

    ret = timerange_valid(ctx, now, result);
    if (ret != EOK) {
        DEBUG(1, ("Cannot check the time range (%d)\n", ret));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(ctx);
    return ret;
}

/*
 * Frees the resources taken by the precompiled rules
 */
static int time_rules_parser_destructor(struct time_rules_ctx *ctx)
{
    int i;

    for (i = 0; i< LP_RGX_MAX; ++i) {
        pcre_free(ctx->re[i]);
        ctx->re[i] = NULL;
    }

    return 0;
}

/*
 * Initializes the parser by precompiling the regular expressions
 * for later use
 */
int init_time_rules_parser(TALLOC_CTX *mem_ctx,
                           struct time_rules_ctx **_out)
{
    const char *errstr;
    int errval;
    int errpos;
    int ret;
    int i;
    struct time_rules_ctx *ctx = NULL;

    ctx = talloc_zero(mem_ctx, struct time_rules_ctx);
    CHECK_PTR(ctx);
    talloc_set_destructor(ctx, time_rules_parser_destructor);

    /* Precompile regular expressions */
    for (i = LP_RGX_GENERALIZED; i< LP_RGX_MAX; ++i) {
        ctx->re[i] = pcre_compile2(lookup_table[i],
                                   0,
                                   &errval,
                                   &errstr,
                                   &errpos,
                                   NULL);

        if (ctx->re[i] == NULL) {
            DEBUG(0, ("Invalid Regular Expression pattern '%s' at position %d"
                      " (Error: %d [%s])\n", lookup_table[i],
                      errpos, errval, errstr));
            ret = EFAULT;
            goto done;
        }

    }

    *_out = ctx;
    return EOK;
done:
    talloc_free(ctx);
    return ret;
}

