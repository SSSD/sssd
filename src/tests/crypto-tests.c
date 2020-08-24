/*
   SSSD

   Crypto tests

   Author: Jakub Hrozek <jhrozek@redhat.com>

   Copyright (C) Red Hat, Inc 2010

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

#include <stdlib.h>
#include <popt.h>
#include <check.h>

#include "util/util.h"
#include "tests/common_check.h"

/* interfaces under test */
#include "util/crypto/sss_crypto.h"

static TALLOC_CTX *test_ctx = NULL;

START_TEST(test_sss_password_encrypt_decrypt)
{
    const char *password[] = { "test123",             /* general */
                               "12345678901234567",   /* just above blocksize */
                               "",                    /* empty */
                               NULL};                 /* sentinel */
    int i;
    char *obfpwd = NULL;
    char *ctpwd = NULL;
    int ret;
    int expected = EOK;

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL, "Failed to allocate memory");
    ck_leaks_push(test_ctx);

    for (i=0; password[i]; i++) {
        ret = sss_password_encrypt(test_ctx, password[i], strlen(password[i])+1,
                                   AES_256, &obfpwd);
        ck_assert_int_eq(ret, expected);

        ret = sss_password_decrypt(test_ctx, obfpwd, &ctpwd);
        ck_assert_int_eq(ret, expected);

        fail_if(ctpwd == NULL,
                "sss_password_decrypt must not return NULL");
        fail_if(strcmp(password[i], ctpwd) != 0,
                "Unexpected decrypted password. Expected: %s got: %s",
                password[i], ctpwd);

        talloc_free(obfpwd);
        talloc_free(ctpwd);
    }

    ck_leaks_pop(test_ctx);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_hmac_sha1)
{
    const char *message = "test message";
    const char *keys[] = {
        "short",
        "proper6789012345678901234567890123456789012345678901234567890123",
        "longlonglonglonglonglonglonglonglonglonglonglonglonglonglonglonglong",
        NULL };
    const char *results[] = {
        "\x2b\x27\x53\x07\x17\xd8\xc0\x8f\x97\x27\xdd\xb3\xec\x41\xd8\xa3\x94\x97\xaa\x35",
        "\x37\xe7\x0a\x6f\x71\x0b\xa9\x93\x81\x53\x8f\x5c\x06\x83\x44\x2f\xc9\x41\xe3\xed",
        "\xbd\x99\xa7\x7f\xfc\x5e\xde\x04\x32\x7f\x7b\x71\x4d\xc0\x3f\x51\x2d\x25\x01\x28",
        NULL };
    unsigned char out[SSS_SHA1_LENGTH];
    int ret, expected;
    int i;
    expected = EOK;

    for (i = 0; keys[i]; i++) {
        ret = sss_hmac_sha1((const unsigned char *)keys[i], strlen(keys[i]),
                            (const unsigned char *)message, strlen(message),
                            out);
        ck_assert_int_eq(ret, expected);
        ck_assert_int_eq(ret, EOK);
        fail_if(memcmp(out, results[i], SSS_SHA1_LENGTH) != 0,
                "Unexpected result for index: %d", i);
    }
}
END_TEST

START_TEST(test_base64_encode)
{
    const unsigned char obfbuf[] = "test";
    const char expected[] = "dGVzdA==";
    char *obfpwd = NULL;

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL, "Failed to allocate memory");
    /* Base64 encode the buffer */
    obfpwd = sss_base64_encode(test_ctx, obfbuf, strlen((const char*)obfbuf));
    fail_if(obfpwd == NULL,
            "sss_base64_encode must not return NULL");
    fail_if(strcmp(obfpwd, expected) != 0,
            "Got: %s expected value: %s", obfpwd, expected);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_base64_decode)
{
    unsigned char *obfbuf = NULL;
    size_t obflen;
    const char b64encoded[] = "dGVzdA==";
    const unsigned char expected[] = "test";

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL, "Failed to allocate memory");
    /* Base64 decode the buffer */
    obfbuf = sss_base64_decode(test_ctx, b64encoded, &obflen);
    fail_if(obfbuf == NULL,
            "sss_base64_decode must not return NULL");
    ck_assert_int_eq(obflen, strlen((const char*)expected));
    fail_if(memcmp(obfbuf, expected, obflen) != 0,
            "Unexpected vale returned after sss_base64_decode");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sss_encrypt_decrypt)
{
    uint8_t key[] = {
        0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7,
        0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    size_t key_len = sizeof(key); /* need to be 32 */
    const char input_text[] = "Secret text";
    const size_t input_text_len = sizeof(input_text) - 1;
    uint8_t *cipher_text;
    size_t cipher_text_len;
    uint8_t *plain_text;
    size_t plain_text_len;
    int ret;

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL, "Failed to allocate memory");

    ret = sss_encrypt(test_ctx, AES256CBC_HMAC_SHA256, key, key_len,
                      (const uint8_t *)input_text, input_text_len,
                      &cipher_text, &cipher_text_len);

    fail_if(ret != 0, "sss_encrypt failed with error: %d", ret);
    fail_if(cipher_text_len == 0, "cipher_text_len must not be zero");

    ret = memcmp(input_text, cipher_text, input_text_len);
    fail_if(ret == 0, "Input and encrypted text has common prefix");

    ret = sss_decrypt(test_ctx, AES256CBC_HMAC_SHA256, key, key_len,
                      cipher_text, cipher_text_len,
                      &plain_text, &plain_text_len);
    fail_if(ret != 0, "sss_decrypt failed with error: %d", ret);
    ck_assert_int_eq(plain_text_len, input_text_len);

    ret = memcmp(plain_text, input_text, input_text_len);
    fail_if(ret != 0, "input text is not the same as de-encrypted text");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_s3crypt_sha512)
{
    int ret;
    char *salt;
    char *userhash;
    char *comphash;
    const char *password = "password123";
    const char *expected_hash = "$6$tU67Q/9h3tm5WJ.U$aL9gjCfiSZQewHTI6A4/MHCVWrMCiJZ.gNXEIw6HO39XGbg.s2nTyGlYXeoQyQtDll3XSbIZN41fJEC3v7ELy0";

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL, "Failed to allocate memory");

    ret = s3crypt_gen_salt(test_ctx, &salt);
    fail_if(ret != 0, "s3crypt_gen_salt failed with error: %d", ret);

    ret = s3crypt_sha512(test_ctx, password, salt, &userhash);
    fail_if(ret != 0, "s3crypt_sha512 failed with error: %d", ret);

    ret = s3crypt_sha512(test_ctx, password, userhash, &comphash);
    fail_if(ret != 0, "s3crypt_sha512 failed with error: %d", ret);
    ck_assert_str_eq(userhash, comphash);
    talloc_free(comphash);

    ret = s3crypt_sha512(test_ctx, password, expected_hash, &comphash);
    fail_if(ret != 0, "s3crypt_sha512 failed with error: %d", ret);
    ck_assert_str_eq(expected_hash, comphash);

    talloc_free(test_ctx);
}
END_TEST

Suite *crypto_suite(void)
{
    Suite *s = suite_create("sss_crypto");

    TCase *tc = tcase_create("sss crypto tests");
    tcase_add_checked_fixture(tc, ck_leak_check_setup, ck_leak_check_teardown);
    /* Do some testing */
    tcase_add_test(tc, test_sss_password_encrypt_decrypt);
    tcase_add_test(tc, test_hmac_sha1);
    tcase_add_test(tc, test_base64_encode);
    tcase_add_test(tc, test_base64_decode);
    tcase_add_test(tc, test_sss_encrypt_decrypt);
    tcase_add_test(tc, test_s3crypt_sha512);
    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc);

    return s;
}


int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int number_failed;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug_level, 0, "Set debug level", NULL },
        POPT_TABLEEND
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

    Suite *s = crypto_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
