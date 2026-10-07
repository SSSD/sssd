/*
    SSSD

    test_nfsidmap.c - Tests for the libnfsidmap plugin

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

#include "config.h"

#include <cmocka.h>
#include <errno.h>
#include <pwd.h>
#include <grp.h>
#include <string.h>
#include <sys/types.h>
#include <nfsidmap.h>
#include <nfsidmap_plugin.h>

#include "util/util_errors.h"


errno_t __real_sss_nss_mc_getpwuid(uid_t uid, struct passwd *result,
                                   char *buffer, size_t buflen);

errno_t __wrap_sss_nss_mc_getpwuid(uid_t uid, struct passwd *result,
                                   char *buffer, size_t buflen)
{
    const char *name;
    size_t name_len;

    name = mock_ptr_type(const char *);
    name_len = strlen(name) + 1;

    if (name_len > buflen) {
        return ERANGE;
    }

    memcpy(buffer, name, name_len);
    result->pw_name = buffer;
    result->pw_uid = uid;

    return 0;
}

errno_t __real_sss_nss_mc_getgrgid(gid_t gid, struct group *result,
                                   char *buffer, size_t buflen);

errno_t __wrap_sss_nss_mc_getgrgid(gid_t gid, struct group *result,
                                   char *buffer, size_t buflen)
{
    const char *name;
    size_t name_len;

    name = mock_ptr_type(const char *);
    name_len = strlen(name) + 1;

    if (name_len > buflen) {
        return ERANGE;
    }

    memcpy(buffer, name, name_len);
    result->gr_name = buffer;
    result->gr_gid = gid;

    return 0;
}

void test_nfsidmap_uid_to_name(void **state)
{
    struct trans_func *trans;
    char name[256];
    int rc;

    trans = libnfsidmap_plugin_init();
    assert_non_null(trans);

    will_return(__wrap_sss_nss_mc_getpwuid, "testuser");

    rc = trans->uid_to_name(12345, NULL, name, sizeof(name));
    assert_int_equal(rc, 0);
    assert_string_equal(name, "testuser");
}

void test_nfsidmap_uid_to_name_short_buffer(void **state)
{
    struct trans_func *trans;
    char name[5];
    int rc;
    size_t c;

    memset(name, 0, sizeof(name));

    trans = libnfsidmap_plugin_init();
    assert_non_null(trans);

    will_return(__wrap_sss_nss_mc_getpwuid, "testuser");

    rc = trans->uid_to_name(12345, NULL, name, sizeof(name));
    assert_int_equal(rc, -2);
    for (c = 0; c < sizeof(name); c++) {
        assert_int_equal(name[c], 0);
    }
}

void test_nfsidmap_gid_to_name(void **state)
{
    struct trans_func *trans;
    char name[256];
    int rc;

    trans = libnfsidmap_plugin_init();
    assert_non_null(trans);

    will_return(__wrap_sss_nss_mc_getgrgid, "testgroup");

    rc = trans->gid_to_name(12345, NULL, name, sizeof(name));
    assert_int_equal(rc, 0);
    assert_string_equal(name, "testgroup");
}

void test_nfsidmap_gid_to_name_short_buffer(void **state)
{
    struct trans_func *trans;
    char name[5];
    int rc;
    size_t c;

    memset(name, 0, sizeof(name));

    trans = libnfsidmap_plugin_init();
    assert_non_null(trans);

    will_return(__wrap_sss_nss_mc_getgrgid, "testgroup");

    rc = trans->gid_to_name(12345, NULL, name, sizeof(name));
    assert_int_equal(rc, -2);
    for (c = 0; c < sizeof(name); c++) {
        assert_int_equal(name[c], 0);
    }
}

int main(int argc, const char *argv[])
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_nfsidmap_uid_to_name),
        cmocka_unit_test(test_nfsidmap_uid_to_name_short_buffer),
        cmocka_unit_test(test_nfsidmap_gid_to_name),
        cmocka_unit_test(test_nfsidmap_gid_to_name_short_buffer),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
