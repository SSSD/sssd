/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests - common code for password expiration tests

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

#include <stdarg.h>
#include <stdlib.h>
#include <stddef.h>
#include <setjmp.h>
#include <unistd.h>
#include <sys/types.h>
#include <cmocka.h>
#include <time.h>

#include "tests/common.h"
#include "tests/cmocka/test_expire_common.h"

#define MAX_VAL 100

static char *now_str(TALLOC_CTX *mem_ctx, const char* format, int s)
{
    time_t t = time(NULL) + s;
    struct tm *tm;
    size_t len;
    char *timestr;

    timestr = talloc_array(mem_ctx, char, MAX_VAL);

    tm = gmtime(&t);
    len = strftime(timestr, MAX_VAL, format, tm);
    if (len == 0) {
        return NULL;
    }

    return timestr;
}

int expire_test_setup(void **state)
{
    struct expire_test_ctx *exp_state;
    TALLOC_CTX *mem_ctx;
    char *past_time;
    char *future_time;
    char *invalid_format;
    char *invalid_longer_format;

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    exp_state = talloc(mem_ctx, struct expire_test_ctx);
    assert_non_null(exp_state);

    *state = exp_state;

    /* testing data */
    invalid_format = now_str(exp_state, "%Y%m%d%H%M%S", -20);
    assert_non_null(invalid_format);

    invalid_longer_format = (void*)now_str(exp_state, "%Y%m%d%H%M%SZA", -20);
    assert_non_null(invalid_longer_format);

    past_time = (void*)now_str(exp_state, "%Y%m%d%H%M%SZ", -20);
    assert_non_null(past_time);

    future_time = (void*)now_str(exp_state, "%Y%m%d%H%M%SZ", 20);
    assert_non_null(future_time);

    exp_state->past_time = past_time;
    exp_state->future_time = future_time;
    exp_state->invalid_format = invalid_format;
    exp_state->invalid_longer_format = invalid_longer_format;

    return 0;
}

int expire_test_teardown(void **state)
{
    struct expire_test_ctx *test_ctx;

    test_ctx = talloc_get_type(*state, struct expire_test_ctx);
    assert_non_null(test_ctx);

    talloc_free(test_ctx);

    return 0;
}

void expire_test_tz(const char* tz,
                    void (*test_func)(void*, void*),
                    void *test_in,
                    void *_test_out)
{
    errno_t ret;
    const char *orig_tz = NULL;

    orig_tz = getenv("TZ");
    if (orig_tz == NULL) {
        orig_tz = "";
    }

    if (tz) {
        ret = setenv("TZ", tz, 1);

        assert_return_code(ret, errno);
    }

    test_func(test_in, _test_out);

    /* restore */
    if (orig_tz != NULL) {
        ret = setenv("TZ", orig_tz, 1);
        assert_return_code(ret, errno);
    }
}
