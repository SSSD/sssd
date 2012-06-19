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
#include "tests/common.h"

/* interfaces under test */
#include "util/crypto/sss_crypto.h"
#include "util/crypto/nss/nss_util.h"

static TALLOC_CTX *test_ctx = NULL;

#ifdef HAVE_NSS
START_TEST(test_nss_init)
{
    int ret;

    ret = nspr_nss_init();
    fail_if(ret != EOK);

    ret = nspr_nss_cleanup();
    fail_if(ret != EOK);
}
END_TEST
#endif

START_TEST(test_encrypt_decrypt)
{
    const char *password[] = { "test123",             /* general */
                               "12345678901234567",   /* just above blocksize */
                               "",                    /* empty */
                               NULL};                 /* sentinel */
    int i;
    char *obfpwd = NULL;
    char *ctpwd = NULL;
    int ret;
    int expected;

#if defined(HAVE_NSS) || defined(HAVE_LIBCRYPTO)
    expected = EOK;
#else
#error Unknown crypto back end
#endif

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL);
    check_leaks_push(test_ctx);

    for (i=0; password[i]; i++) {
        ret = sss_password_encrypt(test_ctx, password[i], strlen(password[i])+1,
                                   AES_256, &obfpwd);
        fail_if(ret != expected);

        ret = sss_password_decrypt(test_ctx, obfpwd, &ctpwd);
        fail_if(ret != expected);

        fail_if(ctpwd && strcmp(password[i], ctpwd) != 0);

        talloc_free(obfpwd);
        talloc_free(ctpwd);
    }

    check_leaks_pop(test_ctx);
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

#if defined(HAVE_NSS) || defined(HAVE_LIBCRYPTO)
    expected = EOK;
#else
#error Unknown crypto back end
#endif

    for (i = 0; keys[i]; i++) {
        ret = sss_hmac_sha1((const unsigned char *)keys[i], strlen(keys[i]),
                            (const unsigned char *)message, strlen(message),
                            out);
        fail_if(ret != expected);
        fail_if(ret == EOK && memcmp(out, results[i], SSS_SHA1_LENGTH) != 0);
    }
}
END_TEST

START_TEST(test_base64_encode)
{
    const unsigned char obfbuf[] = "test";
    const char expected[] = "dGVzdA==";
    char *obfpwd = NULL;

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL);
    /* Base64 encode the buffer */
    obfpwd = sss_base64_encode(test_ctx, obfbuf, strlen((const char*)obfbuf));
    fail_if(obfpwd == NULL);
    fail_if(strcmp(obfpwd,expected) != 0);

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
    fail_if(test_ctx == NULL);
    /* Base64 decode the buffer */
    obfbuf = sss_base64_decode(test_ctx, b64encoded, &obflen);
    fail_if(!obfbuf);
    fail_if(obflen != strlen((const char*)expected));
    fail_if(memcmp(obfbuf, expected, obflen) != 0);

    talloc_free(test_ctx);
}
END_TEST

Suite *crypto_suite(void)
{
    Suite *s = suite_create("sss_crypto");

    TCase *tc = tcase_create("sss crypto tests");
    tcase_add_checked_fixture(tc, leak_check_setup, leak_check_teardown);
    /* Do some testing */
#ifdef HAVE_NSS
    tcase_add_test(tc, test_nss_init);
#endif
    tcase_add_test(tc, test_encrypt_decrypt);
    tcase_add_test(tc, test_hmac_sha1);
    tcase_add_test(tc, test_base64_encode);
    tcase_add_test(tc, test_base64_decode);
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

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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

    CONVERT_AND_SET_DEBUG_LEVEL(debug_level);

    tests_set_cwd();

    Suite *s = crypto_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
