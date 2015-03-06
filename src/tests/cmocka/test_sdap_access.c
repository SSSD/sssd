/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests - sdap access

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

#include "tests/common_check.h"
#include "tests/cmocka/test_expire_common.h"

/* linking against function from sdap_access.c module */
extern bool nds_check_expired(const char *exp_time_str);

static void nds_check_expired_wrap(void *in, void *_out)
{
    *(bool*)_out = nds_check_expired((const char*)in);
}

void test_nds_check_expire(void **state)
{
    struct expire_test_ctx *tc;
    bool res;

    tc = talloc_get_type(*state, struct expire_test_ctx);
    assert_non_null(tc);

    assert_false(nds_check_expired(NULL));
    assert_true(nds_check_expired(tc->invalid_longer_format));
    assert_true(nds_check_expired(tc->invalid_format));
    assert_true(nds_check_expired(tc->past_time));
    assert_false(nds_check_expired(tc->future_time));

    /* changing time zone has no effect as time of expiration is in UTC */
    expire_test_tz("GST+2", nds_check_expired_wrap, (void*)tc->future_time,
                   (void*)&res);
    assert_false(res);
    expire_test_tz("GST-2", nds_check_expired_wrap, (void*)tc->future_time,
                   (void*)&res);
    assert_false(res);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_nds_check_expire,
                                        expire_test_setup,
                                        expire_test_teardown)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
