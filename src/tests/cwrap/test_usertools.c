/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: User utilities

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

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include <popt.h>
#include "util/util.h"
#include "tests/cmocka/common_mock.h"

void test_get_user_num(void **state)
{
    uid_t uid;
    gid_t gid;
    errno_t ret;

    ret = sss_user_by_name_or_uid("123", &uid, &gid);
    assert_int_equal(ret, EOK);
    assert_int_equal(uid, 123);
    assert_int_equal(gid, 456);
}

void test_get_user_str(void **state)
{
    uid_t uid;
    gid_t gid;
    errno_t ret;

    ret = sss_user_by_name_or_uid("sssd", &uid, &gid);
    assert_int_equal(ret, EOK);
    assert_int_equal(uid, 123);
    assert_int_equal(gid, 456);
}

void test_get_user_nullparm(void **state)
{
    uid_t uid;
    gid_t gid;
    errno_t ret;

    ret = sss_user_by_name_or_uid("sssd", &uid, NULL);
    assert_int_equal(ret, EOK);
    assert_int_equal(uid, 123);

    ret = sss_user_by_name_or_uid("sssd", NULL, &gid);
    assert_int_equal(ret, EOK);
    assert_int_equal(gid, 456);
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
        cmocka_unit_test(test_get_user_num),
        cmocka_unit_test(test_get_user_str),
        cmocka_unit_test(test_get_user_nullparm),
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
