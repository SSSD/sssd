/*
    Authors:
        Pavel Reichl <preichl@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests - ldap auth

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

#include "tests/common.h"
#include "providers/ldap/ldap_auth.h"
#include "providers/ldap/ldap_opts.h"
#include "tests/cmocka/test_expire_common.h"

struct check_pwexpire_policy_wrap_indata {
    struct sdap_options *opts;
    enum pwexpire type;
    void *time_fmt;
};

static void check_pwexpire_policy_wrap(void *in, void *_out)
{
    errno_t ret;
    struct check_pwexpire_policy_wrap_indata *data =
        (struct check_pwexpire_policy_wrap_indata*) in;

    ret = check_pwexpire_policy(data->type, data->time_fmt,
                                NULL, 0, data->opts);
    *(errno_t*)_out = ret;
}

static void test_pwexpire_krb(void **state)
{
    struct expire_test_ctx *tc;
    enum pwexpire type = PWEXPIRE_KERBEROS;
    errno_t ret;
    struct sdap_options *opts;
    TALLOC_CTX *mem_ctx;

    mem_ctx = talloc_new(NULL);

    opts = talloc_zero(mem_ctx, struct sdap_options);
    assert_non_null(opts);

    ret = dp_copy_defaults(opts, default_basic_opts,
                           SDAP_OPTS_BASIC, &opts->basic);
    assert_int_equal(ret, ERR_OK);

    tc = talloc_get_type(*state, struct expire_test_ctx);
    assert_non_null(tc);

    ret = check_pwexpire_policy(type,
                                (void*) tc->invalid_longer_format,
                                NULL, 0, opts);
    assert_int_equal(ret, ERR_TIMESPEC_NOT_SUPPORTED);

    ret = check_pwexpire_policy(type, (void*) tc->invalid_format,
                                NULL, 0, opts);
    assert_int_equal(ret, ERR_TIMESPEC_NOT_SUPPORTED);

    ret = check_pwexpire_policy(type, (void*) tc->past_time,
                                NULL, 0, opts);
    assert_int_equal(ret, ERR_PASSWORD_EXPIRED);

    ret = check_pwexpire_policy(type, (void*) tc->future_time,
                                NULL, 0, opts);
    assert_int_equal(ret, EOK);

    /* changing time zone has no effect as time of expiration is in UTC */
    struct check_pwexpire_policy_wrap_indata data;
    data.type = type;
    data.time_fmt = (void*)tc->future_time;
    data.opts = opts;
    expire_test_tz("GST-2",
                   check_pwexpire_policy_wrap,
                   (void*)&data,
                   (void*)&ret);
    assert_int_equal(ret, EOK);

    data.time_fmt = (void*)tc->past_time;
    expire_test_tz("GST-2",
                   check_pwexpire_policy_wrap,
                   (void*)&data,
                   (void*)&ret);
    assert_int_equal(ret, ERR_PASSWORD_EXPIRED);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_pwexpire_krb,
                                        expire_test_setup,
                                        expire_test_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
