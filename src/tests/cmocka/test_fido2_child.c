/*
    SSSD

    Unit test helper child to commmunicate with FIDO2 devices

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

#include <fido/param.h>
#include <popt.h>
#include <termios.h>

#include "tests/cmocka/common_mock.h"

#include "fido2_child/fido2_child.h"

#define TEST_PATH "/test/path"


struct test_state {
    fido_cred_t *cred;
    struct fido2_data data;
    fido_dev_info_t *dev_list;
    size_t dev_number;
    fido_dev_t *dev;
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

    ts->dev_list = fido_dev_info_new(DEVLIST_SIZE);
    assert_non_null(ts->dev_list);
    ts->dev_number = 0;

    ts->dev = fido_dev_new();
    assert_non_null(ts->dev);

    check_leaks_push(ts);
    *state = (void *)ts;
    return 0;
}

static int teardown(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);

    assert_non_null(ts);

    assert_true(check_leaks_pop(ts));
    fido_cred_free(&ts->cred);
    fido_dev_info_free(&ts->dev_list, ts->dev_number);
    if (ts->dev != NULL) {
        fido_dev_close(ts->dev);
    }
    fido_dev_free(&ts->dev);
    talloc_free(ts);
    assert_true(leak_check_teardown());
    return 0;
}

/***********************
 * WRAPPERS
 **********************/
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

/***********************
 * TEST
 **********************/
void test_parse_required_args(void **state)
{
    struct fido2_data data;
    int argc = 0;
    const char *argv[19] = { NULL };
    errno_t ret;

    argv[argc++] = "fido2_child";
    argv[argc++] = "--register";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";

    ret = parse_arguments(argc, argv, &data);

    assert_int_equal(ret, 0);
    assert_int_equal(data.action, ACTION_REGISTER);
    assert_string_equal(data.shortname, "user");
    assert_string_equal(data.domain, "test.com");
    assert_string_equal(data.public_key, "publicKey");
    assert_string_equal(data.key_handle, "keyHandle");
    assert_int_equal(data.type, COSE_ES256);
    assert_int_equal(data.user_verification, FIDO_OPT_OMIT);
    assert_int_equal(data.debug_libfido2, false);
}

void test_parse_all_args(void **state)
{
    struct fido2_data data;
    int argc = 0;
    const char *argv[19] = { NULL };
    errno_t ret;

    argv[argc++] = "fido2_child";
    argv[argc++] = "--authenticate";
    argv[argc++] = "--username=user";
    argv[argc++] = "--domain=test.com";
    argv[argc++] = "--public-key=publicKey";
    argv[argc++] = "--key-handle=keyHandle";
    argv[argc++] = "--type=rs256";
    argv[argc++] = "--user-verification=true";
    argv[argc++] = "--debug-libfido2";

    ret = parse_arguments(argc, argv, &data);

    assert_int_equal(ret, 0);
    assert_int_equal(data.action, ACTION_AUTHENTICATE);
    assert_string_equal(data.shortname, "user");
    assert_string_equal(data.domain, "test.com");
    assert_string_equal(data.public_key, "publicKey");
    assert_string_equal(data.key_handle, "keyHandle");
    assert_int_equal(data.type, COSE_RS256);
    assert_int_equal(data.user_verification, FIDO_OPT_TRUE);
    assert_int_equal(data.debug_libfido2, true);
}

void test_prepare_credentials_ok(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    ts->data.user_verification = FIDO_OPT_TRUE;
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

    ret = list_devices(ts->dev_list, &ts->dev_number);

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
    }

    ret = list_devices(ts->dev_list, &ts->dev_number);

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
    }

    ret = list_devices(ts->dev_list, &ts->dev_number);

    assert_int_equal(ret, FIDO_ERR_INVALID_ARGUMENT);
}

void test_select_device_found(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_OK);

    ret = select_device(ts->dev_list, 0, ts->dev);

    assert_int_equal(ret, FIDO_OK);
}

void test_select_device_open_failed(void **state)
{
    struct test_state *ts = talloc_get_type_abort(*state, struct test_state);
    errno_t ret;

    will_return(__wrap_fido_dev_info_path, TEST_PATH);
    will_return(__wrap_fido_dev_open, FIDO_ERR_INVALID_ARGUMENT);

    ret = select_device(ts->dev_list, 0, ts->dev);

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

void test_register_key_integration(void **state)
{
    struct fido2_data data;
    const char *credentialId = "credentialId";
    const char *userKey = "userKey";
    errno_t ret;

    data.shortname = "user";
    data.domain = "test.com";
    data.type = COSE_ES256;
    data.user_verification = FIDO_OPT_FALSE;
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
    will_return(__wrap_fido_cred_id_ptr, credentialId);
    will_return(__wrap_fido_cred_id_len, strlen(credentialId));
    will_return(__wrap_fido_cred_pubkey_ptr, userKey);
    will_return(__wrap_fido_cred_pubkey_len, strlen(userKey));

    ret = register_key(&data);

    assert_int_equal(ret, EOK);
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
        cmocka_unit_test(test_register_key_integration),
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
