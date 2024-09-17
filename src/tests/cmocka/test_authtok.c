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

#include <string.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#include "util/authtok.h"

#define PIN "ThePIN"


struct test_state {
    struct sss_auth_token *authtoken;
};

static int setup(void **state)
{
    struct test_state *ts = NULL;

    assert_true(leak_check_setup());

    ts = talloc(global_talloc_context, struct test_state);
    assert_non_null(ts);

    ts->authtoken = sss_authtok_new(ts);
    assert_non_null(ts->authtoken);

    check_leaks_push(ts);
    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);

    assert_true(check_leaks_pop(ts));
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
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
    char *data;
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
    assert_string_equal(data, (char *)sss_authtok_get_data(ts->authtoken));

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

    talloc_free(data);
    sss_authtok_set_empty(ts->authtoken);
}

/* Test when type has value SSS_AUTHTOK_TYPE_CCFILE */
static void test_sss_authtok_ccfile(void **state)
{
    size_t len;
    errno_t ret;
    char *data;
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
    assert_string_equal(data, (char *)sss_authtok_get_data(ts->authtoken));

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
    assert_string_equal(data, (char *)sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_ccfile(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    talloc_free(data);
    sss_authtok_set_empty(ts->authtoken);
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
    char *data;
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

    sss_authtok_set_empty(ts->authtoken);
    talloc_free(data);
}

static void test_sss_authtok_copy(void **state)
{
    size_t len;
    errno_t ret;
    char *data;
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

    sss_authtok_set_empty(dest_authtoken);
    type = SSS_AUTHTOK_TYPE_PASSWORD;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);

    ret = sss_authtok_copy(ts->authtoken, dest_authtoken);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(dest_authtoken));
    assert_string_equal(data, (char *)sss_authtok_get_data(dest_authtoken));
    assert_int_equal(len, sss_authtok_get_size(dest_authtoken));

    sss_authtok_set_empty(dest_authtoken);
    talloc_free(dest_authtoken);
    sss_authtok_set_empty(ts->authtoken);
    talloc_free(data);
}

void test_sss_authtok_2fa(void **state)
{
    int ret;
    const char *fa1;
    size_t fa1_size;
    const char *fa2;
    size_t fa2_size;
    struct test_state *ts;

    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_authtok_set_2fa(NULL, "a", 0, "b", 0);
    assert_int_equal(ret, EINVAL);

    /* Test missing first factor */
    ret = sss_authtok_set_2fa(ts->authtoken, NULL, 1, "b", 1);
    assert_int_equal(ret, EINVAL);
    /* Test missing second factor */
    ret = sss_authtok_set_2fa(ts->authtoken, "a", 1, NULL, 1);
    assert_int_equal(ret, EINVAL);
    /* Test wrong first factor length */
    ret = sss_authtok_set_2fa(ts->authtoken, "ab", 1, "b", 1);
    assert_int_equal(ret, EINVAL);
    /* Test wrong second factor length */
    ret = sss_authtok_set_2fa(ts->authtoken, "a", 1, "bc", 1);
    assert_int_equal(ret, EINVAL);

    ret = sss_authtok_set_2fa(ts->authtoken, "a", 1, "bc", 2);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_size(ts->authtoken),
                     2 * sizeof(uint32_t) + 5);
    assert_int_equal(sss_authtok_get_type(ts->authtoken), SSS_AUTHTOK_TYPE_2FA);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\2\0\0\0\3\0\0\0a\0bc\0",
                        2 * sizeof(uint32_t) + 5);
#else
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\0\0\0\2\0\0\0\3a\0bc\0",
                        2 * sizeof(uint32_t) + 5);
#endif

    ret = sss_authtok_get_2fa(ts->authtoken, &fa1, &fa1_size, &fa2, &fa2_size);
    assert_int_equal(ret, EOK);
    assert_int_equal(fa1_size, 1);
    assert_string_equal(fa1, "a");
    assert_int_equal(fa2_size, 2);
    assert_string_equal(fa2, "bc");

    sss_authtok_set_empty(ts->authtoken);

    /* check return code of empty token */
    ret = sss_authtok_get_2fa(ts->authtoken, &fa1, &fa1_size, &fa2, &fa2_size);
    assert_int_equal(ret, ENOENT);

    /* check return code for other token type */
    ret = sss_authtok_set_password(ts->authtoken, "abc", 0);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_2fa(ts->authtoken, &fa1, &fa1_size, &fa2, &fa2_size);
    assert_int_equal(ret, EACCES);

    sss_authtok_set_empty(ts->authtoken);

    /* check return code for garbage */
    ret = sss_authtok_set(ts->authtoken, SSS_AUTHTOK_TYPE_2FA,
                          (const uint8_t *) "1111222233334444", 16);
    assert_int_equal(ret, EINVAL);

    sss_authtok_set_empty(ts->authtoken);
}

void test_sss_authtok_2fa_blobs(void **state)
{
    int ret;
    struct test_state *ts;
    size_t needed_size;
    uint8_t *buf;
    char *fa1;
    size_t fa1_len;
    char *fa2;
    size_t fa2_len;

    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_auth_pack_2fa_blob(NULL, 0, "defg", 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EINVAL);

    ret = sss_auth_pack_2fa_blob("abc", 0, NULL, 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EINVAL);

    ret = sss_auth_pack_2fa_blob("", 0, "defg", 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EINVAL);

    ret = sss_auth_pack_2fa_blob("abc", 0, "", 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EINVAL);

    ret = sss_auth_pack_2fa_blob("abc", 0, "defg", 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EAGAIN);

    buf = talloc_size(ts, needed_size);
    assert_non_null(buf);

    ret = sss_auth_pack_2fa_blob("abc", 0, "defg", 0, buf, needed_size,
                                 &needed_size);
    assert_int_equal(ret, EOK);

#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(buf, "\4\0\0\0\5\0\0\0abc\0defg\0", needed_size);
#else
    assert_memory_equal(buf, "\0\0\0\4\0\0\0\5abc\0defg\0", needed_size);
#endif

    ret = sss_auth_unpack_2fa_blob(ts, buf, needed_size, &fa1, &fa1_len, &fa2,
                                   &fa2_len);
    assert_int_equal(ret, EOK);
    assert_int_equal(fa1_len, 3);
    assert_string_equal(fa1, "abc");
    assert_int_equal(fa2_len, 4);
    assert_string_equal(fa2, "defg");

    talloc_free(buf);
    talloc_free(fa1);
    talloc_free(fa2);
}

void test_sss_authtok_sc_blobs(void **state)
{
    int ret;
    struct test_state *ts;
    size_t needed_size;
    uint8_t *buf;
    const char *pin;
    size_t pin_len;
    const char *token_name;
    size_t token_name_len;
    const char *module_name;
    size_t module_name_len;
    const char *key_id;
    size_t key_id_len;
    const char *label;
    size_t label_len;

    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_auth_pack_sc_blob("abc", 0, "defg", 0, "hijkl", 0, "mnopqr", 0,
                                "stuvw", 0, NULL, 0, &needed_size);
    assert_int_equal(ret, EAGAIN);

    buf = talloc_size(ts, needed_size);
    assert_non_null(buf);

    ret = sss_auth_pack_sc_blob("abc", 0, "defg", 0, "hijkl", 0, "mnopqr", 0,
                                "stuvw", 0, buf, needed_size, &needed_size);
    assert_int_equal(ret, EOK);

#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(buf, "\4\0\0\0\5\0\0\0\6\0\0\0\7\0\0\0\6\0\0\0abc\0defg\0hijkl\0mnopqr\0stuvw\0",
                        needed_size);
#else
    assert_memory_equal(buf, "\0\0\0\4\0\0\0\5\0\0\0\6\0\0\0\7\0\0\0\6abc\0defg\0hijkl\0mnopqr\0stuvw\0",
                        needed_size);
#endif

    pin = sss_auth_get_pin_from_sc_blob(buf, needed_size);
    assert_non_null(pin);
    assert_string_equal(pin, "abc");
    pin = NULL;

    ret = sss_authtok_set(ts->authtoken, SSS_AUTHTOK_TYPE_SC_PIN, buf,
                          needed_size);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_sc(ts->authtoken, &pin, &pin_len,
                             &token_name, &token_name_len,
                             &module_name, &module_name_len,
                             &key_id, &key_id_len,
                             &label, &label_len);
    assert_int_equal(ret, EOK);
    assert_int_equal(pin_len, 3);
    assert_string_equal(pin, "abc");
    assert_int_equal(token_name_len, 4);
    assert_string_equal(token_name, "defg");
    assert_int_equal(module_name_len, 5);
    assert_string_equal(module_name, "hijkl");
    assert_int_equal(key_id_len, 6);
    assert_string_equal(key_id, "mnopqr");
    assert_int_equal(label_len, 5);
    assert_string_equal(label, "stuvw");

    ret = sss_authtok_get_sc(ts->authtoken, NULL, NULL,
                             &token_name, &token_name_len,
                             &module_name, &module_name_len,
                             &key_id, &key_id_len,
                             &label, &label_len);
    assert_int_equal(ret, EOK);
    assert_int_equal(token_name_len, 4);
    assert_string_equal(token_name, "defg");
    assert_int_equal(module_name_len, 5);
    assert_string_equal(module_name, "hijkl");
    assert_int_equal(key_id_len, 6);
    assert_string_equal(key_id, "mnopqr");
    assert_int_equal(label_len, 5);
    assert_string_equal(label, "stuvw");

    ret = sss_authtok_get_sc(ts->authtoken, NULL, NULL,
                             &token_name, NULL,
                             &module_name, NULL,
                             &key_id, NULL,
                             &label, NULL);
    assert_int_equal(ret, EOK);
    assert_string_equal(token_name, "defg");
    assert_string_equal(module_name, "hijkl");
    assert_string_equal(key_id, "mnopqr");
    assert_string_equal(label, "stuvw");

    sss_authtok_set_empty(ts->authtoken);
    talloc_free(buf);
}

#define MISSING_NULL_CHECK do { \
    assert_int_equal(ret, EOK); \
    assert_int_equal(fa1_len, 3); \
    assert_string_equal(fa1, "abc"); \
    assert_int_equal(fa2_len, 4); \
    assert_string_equal(fa2, "defg"); \
 \
    talloc_free(fa1); \
    talloc_free(fa2); \
} while (0)

void test_sss_authtok_2fa_blobs_missing_null(void **state)
{
    int ret;
    struct test_state *ts;
    char *fa1;
    size_t fa1_len;
    char *fa2;
    size_t fa2_len;
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t b0[] = {0x04, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 'a', 'b', 'c', 0x00, 'd', 'e', 'f', 'g', 0x00};
    uint8_t b1[] = {0x03, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 0x00};
    uint8_t b2[] = {0x04, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 'a', 'b', 'c', 0x00, 'd', 'e', 'f', 'g'};
    uint8_t b3[] = {0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 'a', 'b', 'c', 'd', 'e', 'f', 'g'};
#else
    uint8_t b0[] = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x05, 'a', 'b', 'c', 0x00, 'd', 'e', 'f', 'g', 0x00};
    uint8_t b1[] = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x05, 'a', 'b', 'c', 'd', 'e', 'f', 'g', 0x00};
    uint8_t b2[] = {0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c', 0x00, 'd', 'e', 'f', 'g'};
    uint8_t b3[] = {0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 'a', 'b', 'c', 'd', 'e', 'f', 'g'};
#endif


    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_auth_unpack_2fa_blob(ts, b0, sizeof(b0), &fa1, &fa1_len, &fa2,
                                   &fa2_len);
    MISSING_NULL_CHECK;

    ret = sss_auth_unpack_2fa_blob(ts, b1, sizeof(b1), &fa1, &fa1_len, &fa2,
                                   &fa2_len);
    MISSING_NULL_CHECK;

    ret = sss_auth_unpack_2fa_blob(ts, b2, sizeof(b2), &fa1, &fa1_len, &fa2,
                                   &fa2_len);
    MISSING_NULL_CHECK;

    ret = sss_auth_unpack_2fa_blob(ts, b3, sizeof(b3), &fa1, &fa1_len, &fa2,
                                   &fa2_len);
    MISSING_NULL_CHECK;
}

void test_sss_authtok_sc_keypad(void **state)
{
    struct test_state *ts;

    ts = talloc_get_type_abort(*state, struct test_state);

    sss_authtok_set_sc_keypad(NULL);

    sss_authtok_set_sc_keypad(ts->authtoken);
    assert_int_equal(sss_authtok_get_type(ts->authtoken),
                     SSS_AUTHTOK_TYPE_SC_KEYPAD);
    assert_int_equal(sss_authtok_get_size(ts->authtoken), 0);
    assert_null(sss_authtok_get_data(ts->authtoken));
}

void test_sss_authtok_sc_pin(void **state)
{
    struct test_state *ts;
    int ret;
    size_t size;
    const char *pin;
    size_t len;

    ts = talloc_get_type_abort(*state, struct test_state);

    ret = sss_authtok_set_sc_pin(NULL, NULL, 0);
    assert_int_equal(ret, EFAULT);

    ret = sss_authtok_set_sc_pin(ts->authtoken, NULL, 0);
    assert_int_equal(ret, EINVAL);

    ret = sss_authtok_set_sc_pin(ts->authtoken, "12345678", 0);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(ts->authtoken),
                     SSS_AUTHTOK_TYPE_SC_PIN);
    size = sss_authtok_get_size(ts->authtoken);
    assert_int_equal(size, 33);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\11\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0" "12345678\0\0\0\0\0",
                        size);
#else
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\0\0\0\11\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0\1" "12345678\0\0\0\0\0",
                        size);
#endif

    ret = sss_authtok_set_sc_pin(ts->authtoken, "12345678", 5);
    assert_int_equal(ret, EOK);
    assert_int_equal(sss_authtok_get_type(ts->authtoken),
                     SSS_AUTHTOK_TYPE_SC_PIN);
    size = sss_authtok_get_size(ts->authtoken);
    assert_int_equal(size, 30);
#if __BYTE_ORDER == __LITTLE_ENDIAN
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\6\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0" "12345\0\0\0\0\0",
                        size);
#else
    assert_memory_equal(sss_authtok_get_data(ts->authtoken),
                        "\0\0\0\6\0\0\0\1\0\0\0\1\0\0\0\1\0\0\0\1" "12345\0\0\0\0\0",
                        size);
#endif

    ret = sss_authtok_get_sc_pin(ts->authtoken, &pin, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, 5);
    assert_string_equal(pin, "12345");

    sss_authtok_set_empty(ts->authtoken);

    ret = sss_authtok_get_sc_pin(ts->authtoken, &pin, &len);
    assert_int_equal(ret, ENOENT);

    ret = sss_authtok_set_password(ts->authtoken, "12345", 0);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_sc_pin(ts->authtoken, &pin, &len);
    assert_int_equal(ret, EACCES);

    sss_authtok_set_empty(ts->authtoken);

    ret = sss_authtok_get_sc_pin(NULL, &pin, &len);
    assert_int_equal(ret, EFAULT);
}

/* Test when type has value SSS_AUTHTOK_TYPE_2FA_SINGLE */
static void test_sss_authtok_2fa_single(void **state)
{
    size_t len;
    errno_t ret;
    char *data;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    ts = talloc_get_type_abort(*state, struct test_state);
    data = talloc_strdup(ts, "1stfacto2ndfactor");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_2FA_SINGLE;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, (char *)sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_2fa_single(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    ret = sss_authtok_set_2fa_single(ts->authtoken, data, len);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_2fa_single(ts->authtoken, &pwd, &ret_len);
    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    talloc_free(data);
    sss_authtok_set_empty(ts->authtoken);
}

/* Test when type has value SSS_AUTHTOK_TYPE_OAUTH2 */
static void test_sss_authtok_oauth2(void **state)
{
    size_t len;
    errno_t ret;
    char *data;
    size_t ret_len;
    const char *pwd;
    struct test_state *ts;
    enum sss_authtok_type type;

    ts = talloc_get_type_abort(*state, struct test_state);
    data = talloc_strdup(ts, "one-time-password");
    assert_non_null(data);

    len = strlen(data) + 1;
    type = SSS_AUTHTOK_TYPE_OAUTH2;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);

    assert_int_equal(ret, EOK);
    assert_int_equal(type, sss_authtok_get_type(ts->authtoken));
    assert_int_equal(len, sss_authtok_get_size(ts->authtoken));
    assert_string_equal(data, (char *)sss_authtok_get_data(ts->authtoken));

    ret = sss_authtok_get_oauth2(ts->authtoken, &pwd, &ret_len);

    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    ret = sss_authtok_set_oauth2(ts->authtoken, data, len);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_get_oauth2(ts->authtoken, &pwd, &ret_len);
    assert_int_equal(ret, EOK);
    assert_string_equal(data, pwd);
    assert_int_equal(len - 1, ret_len);

    talloc_free(data);
    sss_authtok_set_empty(ts->authtoken);
}

void test_sss_authtok_set_local_passkey_pin(void **state)
{
    struct test_state *ts = NULL;
    enum sss_authtok_type type;
    const char *pin = NULL;
    char *data = NULL;
    size_t len = 0;
    int ret;

    ts = talloc_get_type_abort(*state, struct test_state);
    type = SSS_AUTHTOK_TYPE_PASSKEY;
    data = talloc_strdup(ts, "passkey");
    assert_non_null(data);
    len = strlen(data) + 1;
    ret = sss_authtok_set(ts->authtoken, type, (const uint8_t *)data, len);
    assert_int_equal(ret, EOK);

    ret = sss_authtok_set_local_passkey_pin(ts->authtoken, PIN);
    assert_int_equal(ret, EOK);
    ret = sss_authtok_get_passkey_pin(ts->authtoken, &pin, &len);
    assert_int_equal(ret, EOK);
    assert_int_equal(len, strlen(PIN));
    assert_string_equal(pin, PIN);

    talloc_free(data);
    sss_authtok_set_empty(ts->authtoken);
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
        cmocka_unit_test_setup_teardown(test_sss_authtok_new,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_password,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_ccfile,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_empty,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_wipe_password,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_copy,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_2fa,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_2fa_blobs,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_2fa_blobs_missing_null,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_sc_keypad,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_sc_pin,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_sc_blobs,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_2fa_single,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_oauth2,
                                        setup, teardown),
        cmocka_unit_test_setup_teardown(test_sss_authtok_set_local_passkey_pin,
                                        setup, teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
