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
    char *obfpwd;
    char *ctpwd;
    int ret;

    test_ctx = talloc_new(NULL);
    fail_if(test_ctx == NULL);
    check_leaks_push(test_ctx);

    for (i=0; password[i]; i++) {
        ret = sss_password_encrypt(test_ctx, password[i], strlen(password[i])+1,
                                   AES_256, &obfpwd);
        fail_if(ret != EOK);

        ret = sss_password_decrypt(test_ctx, obfpwd, &ctpwd);
        fail_if(ret != EOK);

        fail_if(strcmp(password[i], ctpwd) != 0);

        talloc_free(obfpwd);
        talloc_free(ctpwd);
    }

    check_leaks_pop(test_ctx);
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
    /* Add all test cases to the test suite */
    suite_add_tcase(s, tc);

    return s;
}


int main(int argc, const char *argv[])
{
    int opt;
    poptContext pc;
    int number_failed;
    int debug = 0;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        { "debug-level", 'd', POPT_ARG_INT, &debug, 0, "Set debug level", NULL },
        POPT_TABLEEND
    };


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

    debug_level = debug;
    tests_set_cwd();

    Suite *s = crypto_suite();
    SRunner *sr = srunner_create(s);
    srunner_run_all(sr, CK_ENV);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
