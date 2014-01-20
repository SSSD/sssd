/*
    SSSD

    authtok - Utilities tests

    Authors:
        Pallavi Jha <pallavikumarijha@gmail.com>

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
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <string.h>

#include "util/authtok.h"


struct test_state {
    struct sss_auth_token *authtoken;
};

static void setup(void **state)
{
    struct test_state *ts = NULL;

    ts = talloc(NULL, struct test_state);
    assert_non_null(ts);

    ts->authtoken = sss_authtok_new(ts);
    assert_non_null(ts->authtoken);

    *state = (void *)ts;
}

static void teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    talloc_free(ts);
}

static void test_sss_authtok_new(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct sss_auth_token *authtoken;

    authtoken = sss_authtok_new(ts);
    assert_non_null(authtoken);

    talloc_free(authtoken);
}

/* @test_authtok_type_x : tests following functions for different value of type
 * sss_authtok_set
 * sss_authtok_get_type
 * sss_authtok_get_size
 * sss_authtok_get_data
 * sss_authtok_get_password
 * sss_authtok_get_ccfile
 *
 * @test_authtok_type_password : type => SSS_AUTHTOK_TYPE_PASSWORD
 * @test_authtok_type_ccfile   : type => SSS_AUTHTOK_TYPE_CCFILE
 * @test_authtok_type_empty    : type => SSS_AUTHTOK_TYPE_EMPTY
 */

/* Test when type has value SSS_AUTHTOK_TYPE_PASSWORD */
static void test_sss_authtok_password(void **state)
{
    size_t len;
    errno_t ret;
    const char *data;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    ts = talloc_get_type_abort(*state, struct test_state);
    data = talloc_strdup(ts, "password");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_password(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    ret = sss_authtok_set_password(ts->authtoken, data, len);

    assert_int_equal(ret, EOK);
    ret = sss_authtok_get_password(ts->authtoken, &pwd, &ret_len);
    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);
}

/* Test when type has value SSS_AUTHTOK_TYPE_CCFILE */
static void test_sss_authtok_ccfile(void **state)
{
    size_t len;
    errno_t ret;
    const char *data;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    ts = talloc_get_type_abort(*state, struct test_state);
    data = talloc_strdup(ts, "path/to/cc_file");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_CCFILE;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    ret = sss_authtok_set_ccfile(ts->authtoken, data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);


    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *) data, 0);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);
}

/* Test when type has value SSS_AUTHTOK_TYPE_EMPTY */
static void test_sss_authtok_empty(void **state)
{
    errno_t ret;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    type = SSS_AUTHTOK_TYPE_EMPTY;
    ts = talloc_get_type_abort(*state, struct test_state);
    ret = sss_authtok_set(ts->authtoken, type, NULL, 0);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(0, sss_authtok_get_size(ts->authtoken));
    assert_null(sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_password(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, ENOENT);

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, ENOENT);

    sss_authtok_set_empty(ts->authtoken);

    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(0, sss_authtok_get_size(ts->authtoken));
    assert_null(sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t*)"", 0);
    assert_int_equal(ret, EOK);

    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(EOK, sss_authtok_get_size(ts->authtoken));
    assert_null(sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_password(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, ENOENT);

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, ENOENT);
}

static void test_sss_authtok_wipe_password(void **state)
{
    size_t len;
    errno_t ret;
    const char *data;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    ts = talloc_get_type_abort(*state, struct test_state);
    data = talloc_strdup(ts, "password");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);

    sss_authtok_wipe_password(ts->authtoken);

    ret = sss_authtok_get_password(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(pwd, "");
    assert_int_equal(len - 1, ret_len);
}

static void test_sss_authtok_copy(void **state)
{
    size_t len;
    errno_t ret;
    const char *data;
    struct test_state *ts;
    enum sss_authtok_type type;
    struct sss_auth_token *dest_authtoken;

    ts= talloc_get_type_abort(*state, struct test_state);

    dest_authtoken = sss_authtok_new(ts);
    assert_non_null(dest_authtoken);

    data = talloc_strdup(ts, "password");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_EMPTY;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(EOK, sss_authtok_copy(ts->authtoken, dest_authtoken));
    assert_int_equal(type, sss_authtok_get_type(dest_authtoken));

    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_copy(ts->authtoken, dest_authtoken);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(dest_authtoken));
    assert_string_equal(data, sss_authtok_get_data(dest_authtoken));
    assert_int_equal(len, sss_authtok_get_size(dest_authtoken));
}

int main(void)
{
    const UnitTest tests[] = {
        unit_test_setup_teardown(test_sss_authtok_new, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok_password, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok_ccfile, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok_empty, setup, teardown),
        unit_test_setup_teardown(test_sss_authtok_wipe_password, setup,
                                 teardown),
        unit_test_setup_teardown(test_sss_authtok_copy, setup, teardown)
    };

    return run_tests(tests);
}
