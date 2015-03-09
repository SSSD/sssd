/*
    SSSD

    find_uid - Utilities tests

    Authors:
        Abhishek Singh <abhishekkumarsingh.cse@gmail.com>

    Copyright (C) 2013 Red Hat

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
#include <dhash.h>

#include "util/find_uid.h"
#include "tests/common.h"

void test_check_if_uid_is_active_success(void **state)
{
    int ret;
    uid_t uid;
    bool result;

    uid = getuid();

    ret = check_if_uid_is_active(uid, &result);
    assert_true(ret == EOK);
    assert_true(result);
}

void test_check_if_uid_is_active_fail(void **state)
{
    int ret;
    uid_t uid;
    bool result;

    uid = (uid_t) -7;

    ret = check_if_uid_is_active(uid, &result);
    assert_true(ret == EOK);
    assert_true(!result);
}

void test_get_uid_table(void **state)
{
    int ret;
    uid_t uid;
    TALLOC_CTX *tmp_ctx;
    hash_table_t *table;
    hash_key_t key;
    hash_value_t value;

    tmp_ctx = talloc_new(NULL);
    assert_true(tmp_ctx != NULL);

    ret = get_uid_table(tmp_ctx, &table);
    assert_true(ret == EOK);

    uid = getuid();
    key.type = HASH_KEY_ULONG;
    key.ul = (unsigned long) uid;

    ret = hash_lookup(table, &key, &value);
    assert_true(ret == HASH_SUCCESS);
    assert_true(hash_delete(table, &key) == HASH_SUCCESS);

    uid = (uid_t) -7;
    key.type = HASH_KEY_ULONG;
    key.ul = (unsigned long) uid;

    ret = hash_lookup(table, &key, &value);
    assert_true(ret == HASH_ERROR_KEY_NOT_FOUND);

    talloc_free(tmp_ctx);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_check_if_uid_is_active_success),
        cmocka_unit_test(test_check_if_uid_is_active_fail),
        cmocka_unit_test(test_get_uid_table)
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
