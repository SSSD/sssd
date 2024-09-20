/*
    SSSD

    Unit test helper child to commmunicate with passkey devices

    Authors:
        Iker Pedrosa <ipedrosa@redhat.com>

    Copyright (C) 2022 Red Hat

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

#include <fido/es256.h>
#include <fido/param.h>
#include <popt.h>
#include <termios.h>

#include "tests/cmocka/common_mock.h"

#include "passkey_child/passkey_child.h"

#define TEST_PATH "/test/path"
#define TEST_KEY_HANDLE "tOGNbhyeyiMJXzqPYbU8DT3Gxwk/LI7QajaW1sEhnNTDHFL5pT189IujIku03gwRJH/1tIKZ7Y8SvmfnOONd6g=="

#define TEST_ES256_PEM_PUBLIC_KEY \
    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEA4ln5Oo8O4pLoSUCuYkXnzHxLiy" \
    "zpCYaysR/8JOJfpW/hMidzU50vqiHv6zLMSh16kntnXWfaGm319a9+8xrYQ=="
static const unsigned char TEST_ES256_HEX_PUBLIC_KEY[64] = {
    0x03, 0x89, 0x67, 0xe4, 0xea, 0x3c, 0x3b, 0x8a,
    0x4b, 0xa1, 0x25, 0x02, 0xb9, 0x89, 0x17, 0x9f,
    0x31, 0xf1, 0x2e, 0x2c, 0xb3, 0xa4, 0x26, 0x1a,
    0xca, 0xc4, 0x7f, 0xf0, 0x93, 0x89, 0x7e, 0x95,
    0xbf, 0x84, 0xc8, 0x9d, 0xcd, 0x4e, 0x74, 0xbe,
    0xa8, 0x87, 0xbf, 0xac, 0xcb, 0x31, 0x28, 0x75,
    0xea, 0x49, 0xed, 0x9d, 0x75, 0x9f, 0x68, 0x69,
    0xb7, 0xd7, 0xd6, 0xbd, 0xfb, 0xcc, 0x6b, 0x61,
};

#define TEST_RS256_PEM_PUBLIC_KEY \
    "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAnlR4slG+GXzLGprDSSo" \
    "v/Zlkdsbbyjg/sGrJwAefXE380QF/aWWrnCrCldlE8+qUayVmVIHuJB3hfX++6n" \
    "aQXL9ZItOgaBpliy+2qDAtJoH6nlnsL+5ZOeJ5GVRU3ySD7mFaZiQre/uCZuSFG" \
    "CB25Uq2y+xDvv2wj/0vadoGnAloepRst1FtTPcT6NUiax66uYXoX6Fm4yB1MBG1" \
    "o8Owcgj/o7vxMgsGxBKjSTAZuf5pDNbhWDbmQSJBv5ZQNVYNkow06iiRiJ6Kqjb" \
    "QD74W3p1fe9pS9/G2KBAFj7kZes8Ym0DN/3jqYSQ7gGgEm0AHmNSU0RhEpe3uGM" \
    "IlUmZC3wIDAQAB"
static const unsigned char TEST_RS256_HEX_PUBLIC_KEY[259] = {
    0x9e, 0x54, 0x78, 0xb2, 0x51, 0xbe, 0x19, 0x7c,
    0xcb, 0x1a, 0x9a, 0xc3, 0x49, 0x2a, 0x2f, 0xfd,
    0x99, 0x64, 0x76, 0xc6, 0xdb, 0xca, 0x38, 0x3f,
    0xb0, 0x6a, 0xc9, 0xc0, 0x07, 0x9f, 0x5c, 0x4d,
    0xfc, 0xd1, 0x01, 0x7f, 0x69, 0x65, 0xab, 0x9c,
    0x2a, 0xc2, 0x95, 0xd9, 0x44, 0xf3, 0xea, 0x94,
    0x6b, 0x25, 0x66, 0x54, 0x81, 0xee, 0x24, 0x1d,
    0xe1, 0x7d, 0x7f, 0xbe, 0xea, 0x76, 0x90, 0x5c,
    0xbf, 0x59, 0x22, 0xd3, 0xa0, 0x68, 0x1a, 0x65,
    0x8b, 0x2f, 0xb6, 0xa8, 0x30, 0x2d, 0x26, 0x81,
    0xfa, 0x9e, 0x59, 0xec, 0x2f, 0xee, 0x59, 0x39,
    0xe2, 0x79, 0x19, 0x54, 0x54, 0xdf, 0x24, 0x83,
    0xee, 0x61, 0x5a, 0x66, 0x24, 0x2b, 0x7b, 0xfb,
    0x82, 0x66, 0xe4, 0x85, 0x18, 0x20, 0x76, 0xe5,
    0x4a, 0xb6, 0xcb, 0xec, 0x43, 0xbe, 0xfd, 0xb0,
    0x8f, 0xfd, 0x2f, 0x69, 0xda, 0x06, 0x9c, 0x09,
    0x68, 0x7a, 0x94, 0x6c, 0xb7, 0x51, 0x6d, 0x4c,
    0xf7, 0x13, 0xe8, 0xd5, 0x22, 0x6b, 0x1e, 0xba,
    0xb9, 0x85, 0xe8, 0x5f, 0xa1, 0x66, 0xe3, 0x20,
    0x75, 0x30, 0x11, 0xb5, 0xa3, 0xc3, 0xb0, 0x72,
    0x08, 0xff, 0xa3, 0xbb, 0xf1, 0x32, 0x0b, 0x06,
    0xc4, 0x12, 0xa3, 0x49, 0x30, 0x19, 0xb9, 0xfe,
    0x69, 0x0c, 0xd6, 0xe1, 0x58, 0x36, 0xe6, 0x41,
    0x22, 0x41, 0xbf, 0x96, 0x50, 0x35, 0x56, 0x0d,
    0x92, 0x8c, 0x34, 0xea, 0x28, 0x91, 0x88, 0x9e,
    0x8a, 0xaa, 0x36, 0xd0, 0x0f, 0xbe, 0x16, 0xde,
    0x9d, 0x5f, 0x7b, 0xda, 0x52, 0xf7, 0xf1, 0xb6,
    0x28, 0x10, 0x05, 0x8f, 0xb9, 0x19, 0x7a, 0xcf,
    0x18, 0x9b, 0x40, 0xcd, 0xff, 0x78, 0xea, 0x61,
    0x24, 0x3b, 0x80, 0x68, 0x04, 0x9b, 0x40, 0x07,
    0x98, 0xd4, 0x94, 0xd1, 0x18, 0x44, 0xa5, 0xed,
    0xee, 0x18, 0xc2, 0x25, 0x52, 0x66, 0x42, 0xdf,
    0x01, 0x00, 0x01
};

#define TEST_EDDSA_PEM_PUBLIC_KEY \
    "MCowBQYDK2VwAyEAr9oDMRm0bGxFmcfNPzlD05i3nFnX71lVl2b4Q2OAia4="
static const unsigned char TEST_EDDSA_HEX_PUBLIC_KEY[32] = {
    0xaf, 0xda, 0x03, 0x31, 0x19, 0xb4, 0x6c, 0x6c,
    0x45, 0x99, 0xc7, 0xcd, 0x3f, 0x39, 0x43, 0xd3,
    0x98, 0xb7, 0x9c, 0x59, 0xd7, 0xef, 0x59, 0x55,
    0x97, 0x66, 0xf8, 0x43, 0x63, 0x80, 0x89, 0xae
};

#define TEST_CRYPTO_CHALLENGE "mZmBWUaJGwEjSNQvkFaicpCzDKhap2pQlfi8FXsv68k="

#define TEST_B64_AUTH_DATA  "authdata"
#define TEST_AUTH_DATA_LEN  6
static const unsigned char TEST_HEX_AUTH_DATA[TEST_AUTH_DATA_LEN] = {
    0x6a, 0xeb, 0x61, 0x75, 0xab, 0x5a
};

#define TEST_B64_SIGNATURE  "signatur"
#define TEST_SIGNATURE_LEN  6
static const unsigned char TEST_HEX_SIGNATURE[TEST_SIGNATURE_LEN] = {
    0xb2, 0x28, 0x27, 0x6a, 0xdb, 0xab
};

struct test_state {
    fido_cred_t *cred;
    struct passkey_data data;
    fido_dev_info_t *dev_list;
    size_t dev_number;
    fido_dev_t *dev;
    fido_assert_t *assert;
};

/***********************
 * SETUP AND TEARDOWN
 **********************/
static int setup(void **state)
{
    struct test_state *ts = NULL;

    assert_true(leak_check_setup());

    ts = talloc(global_talloc_context, struct test_state);
    assert_non_null(ts);

    ts->cred = fido_cred_new();
    assert_non_null(ts->cred);
    ts->data.shortname = "user";
    ts->data.domain = "test.com";
    ts->data.type = COSE_ES256;
    ts->data.user_id = talloc_array(global_talloc_context, unsigned char,
                                    USER_ID_SIZE);
    assert_non_null(ts->data.user_id);

    ts->dev_list = fido_dev_info_new(DEVLIST_SIZE);
    assert_non_null(ts->dev_list);
    ts->dev_number = 0;

    ts->dev = fido_dev_new();
    assert_non_null(ts->dev);

    ts->assert = fido_assert_new();
    assert_non_null(ts->assert);

    check_leaks_push(ts);
    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);
    talloc_free(ts->data.user_id);

    assert_true(check_leaks_pop(ts));
    fido_cred_free(&ts->cred);
    fido_dev_info_free(&ts->dev_list, ts->dev_number);
    if (ts->dev != NULL) {
        fido_dev_close(ts->dev);
    }
    fido_dev_free(&ts->dev);
    fido_assert_free(&ts->assert);
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
}

/***********************
 * WRAPPERS
 **********************/
unsigned int
__wrap_sleep(unsigned int seconds)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_tcgetattr(int fd, struct termios *termios_p)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_tcsetattr(int fd, int optional_actions,
                 const struct termios *termios_p)
{
    int ret;

    ret = mock();

    return ret;
}

ssize_t
__wrap_getline(char **restrict lineptr, size_t *restrict n,
               FILE *restrict stream)
{
    ssize_t ret;

    ret = (ssize_t) mock();
    (*lineptr) = (char *) mock();

    return ret;
}

int
__wrap_fido_dev_info_manifest(fido_dev_info_t *devlist, size_t ilen,
                              size_t *olen)
{
    int ret;

    ret = mock();
    (*olen) = mock();

    return ret;
}

const char *
__wrap_fido_dev_info_path(const fido_dev_info_t *di)
{
    const char *ret;

    ret = (const char *) mock();

    return ret;
}

int
__wrap_fido_dev_open(fido_dev_t *dev, const char *path)
{
    int ret;

    ret = mock();

    return ret;
}

bool
__wrap_fido_dev_has_uv(fido_dev_t *dev)
{
    bool ret;

    ret = mock();

    return ret;
}

bool
__wrap_fido_dev_has_pin(fido_dev_t *dev)
{
    bool ret;

    ret = mock();

    return ret;
}

bool
__wrap_fido_dev_supports_uv(fido_dev_t *dev)
{
    bool ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_dev_make_cred(fido_dev_t *dev, fido_cred_t *cred, const char *pin)
{
    int ret;

    ret = mock();

    return ret;
}

const unsigned char *
__wrap_fido_cred_x5c_ptr(fido_cred_t *cred)
{
    const unsigned char *ret;

    ret = (const unsigned char *) mock();

    return ret;
}

int
__wrap_fido_cred_verify(fido_cred_t *cred)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_cred_verify_self(fido_cred_t *cred)
{
    int ret;

    ret = mock();

    return ret;
}

const unsigned char *
__wrap_fido_cred_id_ptr(const fido_cred_t *cred)
{
    const unsigned char *ret;

    ret = (const unsigned char *) mock();

    return ret;
}

int
__wrap_fido_cred_id_len(fido_cred_t *cred)
{
    int ret;

    ret = mock();

    return ret;
}

const unsigned char *
__wrap_fido_cred_pubkey_ptr(const fido_cred_t *cred)
{
    const unsigned char *ret;

    ret = (const unsigned char *) mock();

    return ret;
}

int
__wrap_fido_cred_pubkey_len(fido_cred_t *cred)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_set_rp(fido_assert_t *assert, const char *id)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_allow_cred(fido_assert_t *assert, const unsigned char *ptr,
                              size_t len)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_set_uv(fido_assert_t *assert, fido_opt_t uv)
{
    int ret;

    ret = mock();

    return ret;
}

size_t
__wrap_fido_assert_user_id_len(const fido_assert_t *assert, size_t size)
{
    size_t ret;

    ret = (size_t) mock();

    return ret;
}

int
__wrap_fido_assert_set_clientdata_hash(fido_assert_t *assert,
                                       const unsigned char *ptr, size_t len)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_dev_get_assert(fido_dev_t *dev, fido_assert_t *assert,
                           const char *pin)
{
    int ret;

    ret = mock();

    return ret;
}

bool
__wrap_fido_dev_is_fido2(const fido_dev_t *dev)
{
    bool ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_verify(const fido_assert_t *assert, size_t idx,
                          int cose_alg, const void *pk)
{
    int ret;

    ret = mock();

    return ret;
}

const unsigned char *
__wrap_fido_assert_authdata_ptr(const fido_assert_t *assert, size_t idx)
{
    const unsigned char *ret;

    ret = (const unsigned char *) mock();

    return ret;
}

size_t
__wrap_fido_assert_authdata_len(const fido_assert_t *assert, size_t idx)
{
    size_t ret;

    ret = (size_t) mock();

    return ret;
}

const unsigned char *
__wrap_fido_assert_sig_ptr(const fido_assert_t *assert, size_t idx)
{
    const unsigned char *ret;

    ret = (const unsigned char *) mock();

    return ret;
}

size_t
__wrap_fido_assert_sig_len(const fido_assert_t *assert, size_t idx)
{
    size_t ret;

    ret = (size_t) mock();

    return ret;
}

int
__wrap_fido_assert_set_count(fido_assert_t *assert, size_t n)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_set_authdata(fido_assert_t *assert, size_t idx,
                                const unsigned char *ptr, size_t len)
{
    int ret;

    ret = mock();

    return ret;
}

int
__wrap_fido_assert_set_sig(fido_assert_t *assert, size_t idx,
                           const unsigned char *ptr, size_t len)
{
    int ret;

    ret = mock();

    return ret;
}

/***********************
 * TEST
 **********************/
void test_parse_required_args(void **state)
{
    TALLOC_CTX *test_ctx;
    struct passkey_data data;
    int argc = 0;
    const char *argv[19] = { NULL };
    errno_t ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    argv[argc++] = "passkey_child";
    argv[argc++] = "--register";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";

    ret = parse_arguments(test_ctx, argc, argv, &data);

    assert_int_equal(ret, 0);
    assert_int_equal(data.action, ACTION_REGISTER);
    assert_string_equal(data.shortname, "user");
    assert_string_equal(data.domain, "test.com");
    assert_string_equal(data.public_key_list[0], "publicKey");
    assert_string_equal(data.key_handle_list[0], "keyHandle");
    assert_int_equal(data.type, COSE_ES256);
    assert_int_equal(data.user_verification, FIDO_OPT_OMIT);
    assert_int_equal(data.cred_type, CRED_SERVER_SIDE);
    assert_int_equal(data.debug_libfido2, false);

    talloc_free(test_ctx);
}

void test_parse_all_args(void **state)
{
    TALLOC_CTX *test_ctx;
    struct passkey_data data;
    int argc = 0;
    const char *argv[19] = { NULL };
    errno_t ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);
    argv[argc++] = "passkey_child";
    argv[argc++] = "--authenticate";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";
    argv[argc++] = "--cryptographic-challenge=crypto";
    argv[argc++] = "--auth-data=auth";
    argv[argc++] = "--signature=sign";
    argv[argc++] = "--type=rs256";
    argv[argc++] = "--user-verification=true";
    argv[argc++] = "--cred-type=discoverable";
    argv[argc++] = "--debug-libfido2";

    ret = parse_arguments(test_ctx, argc, argv, &data);

    assert_int_equal(ret, 0);
    assert_int_equal(data.action, ACTION_AUTHENTICATE);
    assert_string_equal(data.shortname, "user");
    assert_string_equal(data.domain, "test.com");
    assert_string_equal(data.public_key_list[0], "publicKey");
    assert_string_equal(data.key_handle_list[0], "keyHandle");
    assert_string_equal(data.crypto_challenge, "crypto");
    assert_string_equal(data.auth_data, "auth");
    assert_string_equal(data.signature, "sign");
    assert_int_equal(data.type, COSE_RS256);
    assert_int_equal(data.user_verification, FIDO_OPT_TRUE);
    assert_int_equal(data.cred_type, CRED_DISCOVERABLE);
    assert_int_equal(data.debug_libfido2, true);

    talloc_free(test_ctx);
}

void test_prepare_credentials_ok(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_TRUE;
    ts->data.cred_type = CRED_SERVER_SIDE;
    will_return(__wrap_fido_dev_has_uv, true);
    will_return(__wrap_fido_dev_has_pin, false);

    ret = prepare_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, FIDO_OK);
    assert_string_equal(fido_cred_user_name(ts->cred), "user");
    assert_string_equal(fido_cred_rp_id(ts->cred), "test.com");
    assert_string_equal(fido_cred_rp_name(ts->cred), "test.com");
    assert_int_equal(fido_cred_type(ts->cred), COSE_ES256);
}

void test_prepare_credentials_user_verification_missing(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_TRUE;
    ts->data.cred_type = CRED_SERVER_SIDE;
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);

    ret = prepare_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, EINVAL);
}

void test_prepare_credentials_error(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    // Set the type to an incorrect value intentionally
    ts->data.type = 0;

    ret = prepare_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
}

void test_list_devices_one_device(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
    will_return(__wrap_fido_dev_info_manifest, 1);

    ret = list_devices(TIMEOUT, ts->dev_list, &ts->dev_number);

    assert_int_equal(ret, FIDO_OK);
    assert_int_equal(ts->dev_number, 1);
}

void test_list_devices_no_device(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    for (int i = 0; i < TIMEOUT; i += FREQUENCY) {
        will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
        will_return(__wrap_fido_dev_info_manifest, 0);
        if (i < (TIMEOUT - 1)) {
            will_return(__wrap_sleep, 0);
        }
    }

    ret = list_devices(TIMEOUT, ts->dev_list, &ts->dev_number);

    assert_int_equal(ret, FIDO_OK);
    assert_int_equal(ts->dev_number, 0);
}

void test_list_devices_error(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    for (int i = 0; i < TIMEOUT; i += FREQUENCY) {
        will_return(__wrap_fido_dev_info_manifest, FIDO_ERR_INVALID_ARGUMENT);
        will_return(__wrap_fido_dev_info_manifest, 0);
        if (i < (TIMEOUT - 1)) {
            will_return(__wrap_sleep, 0);
        }
    }

    ret = list_devices(TIMEOUT, ts->dev_list, &ts->dev_number);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
}

void test_select_device_found(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);

    ret = select_device(ACTION_REGISTER, ts->dev_list, 1, NULL, &dev);

    assert_int_equal(ret, FIDO_OK);
    fido_dev_close(dev);
    fido_dev_free(&dev);
}

void test_select_device_open_failed(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_ERR_INVALID_ARGUMENT);

    ret = select_device(ACTION_REGISTER, ts->dev_list, 1, NULL, &dev);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
}

void test_read_pass(void **state)
{
    ssize_t test_len = 6;
    char *pin = NULL;
    char *expected_pin = malloc(test_len);
    ssize_t bytes_read;

    snprintf(expected_pin, test_len, "%s\n", "1234");
    will_return(__wrap_tcgetattr, 0);
    will_return(__wrap_tcsetattr, 0);
    will_return(__wrap_getline, test_len);
    will_return(__wrap_getline, expected_pin);
    will_return(__wrap_tcsetattr, 0);

    bytes_read = read_pin(&pin);

    assert_int_equal(bytes_read, test_len - 1);
    assert_string_equal(pin, expected_pin);

    free(expected_pin);
}

void test_generate_credentials_user_verification(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.quiet = false;
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_make_cred, FIDO_OK);

    ret = generate_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, FIDO_OK);
}

void test_generate_credentials_pin(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    ssize_t test_len = 6;
    char *pin = malloc(test_len);
    errno_t ret;

    ts->data.quiet = false;
    snprintf(pin, test_len, "%s\n", "1234");
    will_return(__wrap_fido_dev_has_pin, true);
    will_return(__wrap_tcgetattr, 0);
    will_return(__wrap_tcsetattr, 0);
    will_return(__wrap_getline, test_len);
    will_return(__wrap_getline, pin);
    will_return(__wrap_tcsetattr, 0);
    will_return(__wrap_fido_dev_make_cred, FIDO_OK);

    ret = generate_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, FIDO_OK);
}

void test_generate_credentials_pin_error(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    char *expected_pin;
    errno_t ret;

    ts->data.quiet = false;
    will_return(__wrap_fido_dev_has_pin, true);
    will_return(__wrap_tcgetattr, 0);
    will_return(__wrap_tcsetattr, 0);
    will_return(__wrap_getline, -1);
    will_return(__wrap_getline, expected_pin);
    will_return(__wrap_tcsetattr, 0);

    ret = generate_credentials(&ts->data, ts->dev, ts->cred);

    assert_int_equal(ret, ERR_INPUT_PARSE);
}

void test_verify_credentials_basic_attestation(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_cred_x5c_ptr, "mock");
    will_return(__wrap_fido_cred_verify,  FIDO_OK);

    ret = verify_credentials(ts->cred);

    assert_int_equal(ret, FIDO_OK);
}

void test_verify_credentials_self_attestation(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_cred_x5c_ptr, NULL);
    will_return(__wrap_fido_cred_verify_self,  FIDO_OK);

    ret = verify_credentials(ts->cred);

    assert_int_equal(ret, FIDO_OK);
}

void test_verify_credentials_error(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_cred_x5c_ptr, "mock");
    will_return(__wrap_fido_cred_verify,  FIDO_ERR_INVALID_ARGUMENT);

    ret = verify_credentials(ts->cred);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
}

void test_decode_public_key(void **state)
{
    TALLOC_CTX *test_ctx = NULL;
    struct passkey_data data;
    char *pem_key = NULL;
    errno_t ret;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    data.type = COSE_ES256;
    ret = public_key_to_base64(test_ctx, &data, TEST_ES256_HEX_PUBLIC_KEY, 64,
                               &pem_key);
    assert_int_equal(ret, EOK);
    assert_string_equal(pem_key, TEST_ES256_PEM_PUBLIC_KEY);

    data.type = COSE_RS256;
    ret = public_key_to_base64(test_ctx, &data, TEST_RS256_HEX_PUBLIC_KEY, 259,
                               &pem_key);
    assert_int_equal(ret, EOK);
    assert_string_equal(pem_key, TEST_RS256_PEM_PUBLIC_KEY);

    data.type = COSE_EDDSA;
    ret = public_key_to_base64(test_ctx, &data, TEST_EDDSA_HEX_PUBLIC_KEY, 32,
                               &pem_key);
    assert_int_equal(ret, EOK);
    assert_string_equal(pem_key, TEST_EDDSA_PEM_PUBLIC_KEY);

    talloc_free(test_ctx);
}

void test_register_key_integration(void **state)
{
    struct passkey_data data;
    const char *credential_id = "credential_id";
    errno_t ret;

    data.action = ACTION_REGISTER;
    data.shortname = "user";
    data.domain = "test.com";
    data.type = COSE_ES256;
    data.user_verification = FIDO_OPT_FALSE;
    data.cred_type = CRED_SERVER_SIDE;
    data.mapping_file = NULL;
    data.quiet = false;
    will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
    will_return(__wrap_fido_dev_info_manifest, 1);
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_make_cred, FIDO_OK);
    will_return(__wrap_fido_cred_x5c_ptr, "mock");
    will_return(__wrap_fido_cred_verify, FIDO_OK);
    will_return(__wrap_fido_cred_id_ptr, credential_id);
    will_return(__wrap_fido_cred_id_len, strlen(credential_id));
    will_return(__wrap_fido_cred_pubkey_ptr, TEST_ES256_HEX_PUBLIC_KEY);
    will_return(__wrap_fido_cred_pubkey_len, 64);

    ret = register_key(&data, TIMEOUT);

    assert_int_equal(ret, EOK);
}

void test_select_authenticator(void **state)
{
    TALLOC_CTX *tmp_ctx;
    struct passkey_data data;
    fido_dev_t *dev = NULL;
    fido_assert_t *assert = NULL;
    int index = 0;
    char *key_handle;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);
    data.action = ACTION_GET_ASSERT;
    data.domain = "test.com";
    key_handle = talloc_strdup(tmp_ctx, TEST_KEY_HANDLE);
    data.key_handle_list = &key_handle;
    data.key_handle_size = 1;
    data.crypto_challenge = TEST_CRYPTO_CHALLENGE;
    will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
    will_return(__wrap_fido_dev_info_manifest, 1);
    will_return(__wrap_fido_assert_set_rp, FIDO_OK);
    will_return(__wrap_fido_assert_allow_cred, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);

    ret = select_authenticator(&data, TIMEOUT, &dev, &assert, &index);

    assert_int_equal(ret, FIDO_OK);

    if (dev != NULL) {
        fido_dev_close(dev);
    }
    fido_dev_free(&dev);
    fido_assert_free(&assert);
    talloc_free(tmp_ctx);
}

void test_prepare_assert_ok(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.action = ACTION_AUTHENTICATE;
    ts->data.key_handle_list = talloc_array(ts, char*, 1);
    ts->data.key_handle_list[0] = talloc_strdup(ts, "a2V5SGFuZGxl");
    will_return(__wrap_fido_assert_set_rp, FIDO_OK);
    will_return(__wrap_fido_assert_allow_cred, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);

    ret = prepare_assert(&ts->data, 0, ts->assert);

    assert_int_equal(ret, FIDO_OK);
    talloc_free(ts->data.key_handle_list[0]);
    talloc_free(ts->data.key_handle_list);
}

void test_prepare_assert_error(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.action = ACTION_AUTHENTICATE;
    ts->data.key_handle_list = talloc_array(ts, char*, 1);
    ts->data.key_handle_list[0] = talloc_strdup(ts, "a2V5SGFuZGxl");
    will_return(__wrap_fido_assert_set_rp, FIDO_ERR_INVALID_ARGUMENT);

    ret = prepare_assert(&ts->data, 0, ts->assert);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
    talloc_free(ts->data.key_handle_list[0]);
    talloc_free(ts->data.key_handle_list);
}

void test_reset_public_key(void **state)
{
    struct pk_data_t pk_data;
    errno_t ret;

    pk_data.type = COSE_ES256;
    pk_data.public_key = es256_pk_new();

    ret = reset_public_key(&pk_data);

    assert_int_equal(ret, EOK);
}

void test_encode_public_keys(void **state)
{
    struct pk_data_t pk_data;
    errno_t ret;

    ret = public_key_to_libfido2(TEST_ES256_PEM_PUBLIC_KEY, &pk_data);
    assert_int_equal(ret, FIDO_OK);
    assert_memory_equal(pk_data.public_key, TEST_ES256_HEX_PUBLIC_KEY, 64);
    reset_public_key(&pk_data);

    ret = public_key_to_libfido2(TEST_RS256_PEM_PUBLIC_KEY, &pk_data);
    assert_int_equal(ret, FIDO_OK);
    assert_memory_equal(pk_data.public_key, TEST_RS256_HEX_PUBLIC_KEY, 259);
    reset_public_key(&pk_data);

    ret = public_key_to_libfido2(TEST_EDDSA_PEM_PUBLIC_KEY, &pk_data);
    assert_int_equal(ret, FIDO_OK);
    assert_memory_equal(pk_data.public_key, TEST_EDDSA_HEX_PUBLIC_KEY, 32);
    reset_public_key(&pk_data);
}

void test_get_authenticator_data_one_key(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);

    ret = select_device(ACTION_AUTHENTICATE, ts->dev_list, 1, ts->assert, &dev);

    assert_int_equal(ret, FIDO_OK);
    assert_non_null(dev);
    fido_dev_close(dev);
    fido_dev_free(&dev);
}

void test_get_authenticator_data_multiple_keys_assert_found(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    // Key 1
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_ERR_INVALID_SIG);
    // Key 2
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);

    ret = select_device(ACTION_AUTHENTICATE, ts->dev_list, 2, ts->assert, &dev);

    assert_int_equal(ret, FIDO_OK);
    assert_non_null(dev);
    fido_dev_close(dev);
    fido_dev_free(&dev);
}

void test_get_authenticator_data_multiple_keys_assert_not_found(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    // Key 1
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_ERR_INVALID_SIG);
    // Key 2
    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);
    will_return(__wrap_fido_dev_is_fido2, true);
    will_return(__wrap_fido_dev_get_assert, FIDO_ERR_INVALID_SIG);

    ret = select_device(ACTION_AUTHENTICATE, ts->dev_list, 2, ts->assert, &dev);

    assert_int_equal(ret, FIDO_ERR_NOTFOUND);
    assert_null(dev);
}

void test_get_device_options(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_TRUE;
    will_return(__wrap_fido_dev_has_uv, true);
    will_return(__wrap_fido_dev_has_pin, true);
    will_return(__wrap_fido_dev_supports_uv, true);

    ret = get_device_options(dev, &ts->data);

    assert_int_equal(ret, FIDO_OK);
    assert_int_equal(ts->data.user_verification, FIDO_OPT_TRUE);
}

void test_get_device_options_user_verification_unmatch(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_TRUE;
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_supports_uv, false);

    ret = get_device_options(dev, &ts->data);

    assert_int_equal(ret, EINVAL);
}

void test_get_device_options_user_verification_false_not_supported(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    fido_dev_t *dev = NULL;
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_FALSE;
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_supports_uv, false);

    ret = get_device_options(dev, &ts->data);

    assert_int_equal(ret, FIDO_OK);
    assert_int_equal(ts->data.user_verification, FIDO_OPT_OMIT);
}

void test_request_assert(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_FALSE;
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);

    ret = request_assert(&ts->data, ts->dev, ts->assert);

    assert_int_equal(ret, FIDO_OK);
}

void test_verify_assert(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct pk_data_t pk_data;
    errno_t ret;

    pk_data.type = COSE_ES256;
    pk_data.public_key = es256_pk_new();
    ts->data.user_verification = FIDO_OPT_FALSE;
    will_return(__wrap_fido_assert_verify, FIDO_OK);

    ret = verify_assert(&pk_data, ts->assert);

    assert_int_equal(ret, FIDO_OK);

    reset_public_key(&pk_data);
}

void test_verify_assert_failed(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    struct pk_data_t pk_data;
    errno_t ret;

    pk_data.type = COSE_ES256;
    pk_data.public_key = es256_pk_new();
    ts->data.user_verification = FIDO_OPT_FALSE;
    will_return(__wrap_fido_assert_verify, FIDO_ERR_TX);

    ret = verify_assert(&pk_data, ts->assert);

    assert_int_equal(ret, FIDO_ERR_TX);

    reset_public_key(&pk_data);
}

void test_authenticate_integration(void **state)
{
    TALLOC_CTX *tmp_ctx;
    struct passkey_data data;
    size_t dev_number = 3;
    char *key_handle;
    char *public_key;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);
    data.action = ACTION_AUTHENTICATE;
    data.shortname = "user";
    data.domain = "test.com";
    key_handle = talloc_strdup(tmp_ctx, TEST_KEY_HANDLE);
    public_key = talloc_strdup(tmp_ctx, TEST_ES256_PEM_PUBLIC_KEY);
    data.key_handle_list = &key_handle;
    data.key_handle_size = 1;
    data.public_key_list = &public_key;
    data.public_key_size = 1;
    data.type = COSE_ES256;
    data.user_verification = FIDO_OPT_FALSE;
    data.user_id = NULL;
    data.quiet = false;
    will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
    will_return(__wrap_fido_dev_info_manifest, dev_number);
    will_return(__wrap_fido_assert_set_rp, FIDO_OK);
    will_return(__wrap_fido_assert_allow_cred, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);
    for (size_t i = 0; i < (dev_number - 1); i++) {
        will_return(__wrap_fido_dev_info_path, TEST_PATH);
        will_return(__wrap_fido_dev_open, FIDO_OK);
        will_return(__wrap_fido_dev_is_fido2, true);
        if (i == 0) {
            will_return(__wrap_fido_dev_get_assert, FIDO_ERR_INVALID_SIG);
        } else {
            will_return(__wrap_fido_dev_get_assert, FIDO_OK);
        }
    }
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_supports_uv, false);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_verify, FIDO_OK);

    ret = authenticate(&data, TIMEOUT);

    assert_int_equal(ret, EOK);
    talloc_free(tmp_ctx);
}

void test_get_assert_data_integration(void **state)
{
    TALLOC_CTX *tmp_ctx;
    struct passkey_data data;
    size_t dev_number = 3;
    char *key_handle;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);
    data.action = ACTION_GET_ASSERT;
    data.domain = "test.com";
    key_handle = talloc_strdup(tmp_ctx, TEST_KEY_HANDLE);
    data.key_handle_list = &key_handle;
    data.key_handle_size = 1;
    data.crypto_challenge = TEST_CRYPTO_CHALLENGE;
    data.user_verification = FIDO_OPT_FALSE;
    data.user_id = NULL;
    will_return(__wrap_fido_dev_info_manifest, FIDO_OK);
    will_return(__wrap_fido_dev_info_manifest, dev_number);
    will_return(__wrap_fido_assert_set_rp, FIDO_OK);
    will_return(__wrap_fido_assert_allow_cred, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);
    for (size_t i = 0; i < (dev_number - 1); i++) {
        will_return(__wrap_fido_dev_info_path, TEST_PATH);
        will_return(__wrap_fido_dev_open, FIDO_OK);
        will_return(__wrap_fido_dev_is_fido2, true);
        if (i == 0) {
            will_return(__wrap_fido_dev_get_assert, FIDO_ERR_INVALID_SIG);
        } else {
            will_return(__wrap_fido_dev_get_assert, FIDO_OK);
        }
    }
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_supports_uv, false);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_dev_has_uv, false);
    will_return(__wrap_fido_dev_has_pin, false);
    will_return(__wrap_fido_dev_get_assert, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_authdata_ptr, TEST_HEX_AUTH_DATA);
    will_return(__wrap_fido_assert_authdata_len, TEST_AUTH_DATA_LEN);
    will_return(__wrap_fido_assert_sig_ptr, TEST_HEX_SIGNATURE);
    will_return(__wrap_fido_assert_sig_len, TEST_SIGNATURE_LEN);

    ret = get_assert_data(&data, TIMEOUT);

    assert_int_equal(ret, EOK);
    talloc_free(tmp_ctx);
}

void test_verify_assert_data_integration(void **state)
{
    TALLOC_CTX *tmp_ctx;
    struct passkey_data data;
    char *key_handle;
    char *public_key;
    errno_t ret;

    tmp_ctx = talloc_new(NULL);
    assert_non_null(tmp_ctx);
    data.action = ACTION_VERIFY_ASSERT;
    data.domain = "test.com";
    key_handle = talloc_strdup(tmp_ctx, TEST_KEY_HANDLE);
    public_key = talloc_strdup(tmp_ctx, TEST_ES256_PEM_PUBLIC_KEY);
    data.key_handle_list = &key_handle;
    data.key_handle_size = 1;
    data.public_key_list = &public_key;
    data.public_key_size = 1;
    data.crypto_challenge = TEST_CRYPTO_CHALLENGE;
    data.auth_data = TEST_B64_AUTH_DATA;
    data.signature = TEST_B64_SIGNATURE;
    will_return(__wrap_fido_assert_set_rp, FIDO_OK);
    will_return(__wrap_fido_assert_allow_cred, FIDO_OK);
    will_return(__wrap_fido_assert_set_uv, FIDO_OK);
    will_return(__wrap_fido_assert_set_clientdata_hash, FIDO_OK);
    will_return(__wrap_fido_assert_set_count, FIDO_OK);
    will_return(__wrap_fido_assert_set_authdata, FIDO_OK);
    will_return(__wrap_fido_assert_set_sig, FIDO_OK);
    will_return(__wrap_fido_assert_verify, FIDO_OK);

    ret = verify_assert_data(&data);

    assert_int_equal(ret, EOK);
    talloc_free(tmp_ctx);
}

static void test_parse_supp_valgrind_args(void)
{
    /*
     * The objective of this function is to filter the unit-test functions
     * that trigger a valgrind memory leak and suppress them to avoid false
     * positives.
     */
    DEBUG_CLI_INIT(debug_level);
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
        cmocka_unit_test(test_parse_required_args),
        cmocka_unit_test(test_parse_all_args),
        cmocka_unit_test_setup_teardown(test_prepare_credentials_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(test_prepare_credentials_user_verification_missing, setup, teardown),
        cmocka_unit_test_setup_teardown(test_prepare_credentials_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_list_devices_one_device, setup, teardown),
        cmocka_unit_test_setup_teardown(test_list_devices_no_device, setup, teardown),
        cmocka_unit_test_setup_teardown(test_list_devices_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_select_device_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_select_device_open_failed, setup, teardown),
        cmocka_unit_test(test_read_pass),
        cmocka_unit_test_setup_teardown(test_generate_credentials_user_verification, setup, teardown),
        cmocka_unit_test_setup_teardown(test_generate_credentials_pin, setup, teardown),
        cmocka_unit_test_setup_teardown(test_generate_credentials_pin_error, setup, teardown),
        cmocka_unit_test_setup_teardown(test_verify_credentials_basic_attestation, setup, teardown),
        cmocka_unit_test_setup_teardown(test_verify_credentials_self_attestation, setup, teardown),
        cmocka_unit_test_setup_teardown(test_verify_credentials_error, setup, teardown),
        cmocka_unit_test(test_decode_public_key),
        cmocka_unit_test(test_register_key_integration),
        cmocka_unit_test(test_select_authenticator),
        cmocka_unit_test_setup_teardown(test_prepare_assert_ok, setup, teardown),
        cmocka_unit_test_setup_teardown(test_prepare_assert_error, setup, teardown),
        cmocka_unit_test(test_reset_public_key),
        cmocka_unit_test(test_encode_public_keys),
        cmocka_unit_test_setup_teardown(test_get_authenticator_data_one_key, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_authenticator_data_multiple_keys_assert_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_authenticator_data_multiple_keys_assert_not_found, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_device_options, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_device_options_user_verification_unmatch, setup, teardown),
        cmocka_unit_test_setup_teardown(test_get_device_options_user_verification_false_not_supported, setup, teardown),
        cmocka_unit_test_setup_teardown(test_request_assert, setup, teardown),
        cmocka_unit_test_setup_teardown(test_verify_assert, setup, teardown),
        cmocka_unit_test_setup_teardown(test_verify_assert_failed, setup, teardown),
        cmocka_unit_test(test_authenticate_integration),
        cmocka_unit_test(test_get_assert_data_integration),
        cmocka_unit_test(test_verify_assert_data_integration),
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

    test_parse_supp_valgrind_args();

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
