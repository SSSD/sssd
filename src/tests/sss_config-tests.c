/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <check.h>
#include <stdio.h>
#include <talloc.h>
#include <errno.h>
#include <string.h>
#include <sys/stat.h>
#include "util/util.h"
#include "util/sss_config.h"
#include "tests/common.h"
#include "tests/common_check.h"

#define TEST_SUBDIR "test_sss_config"
#define TEST_FILE TEST_SUBDIR "/sss_config_test.conf"
#define TEST_FILE_BACKUP TEST_FILE ".augsave"

/* input files */

const char *test_orig =
"[sssd]\n\
services = nss, pam\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_svc_one =
"[sssd]\n\
services = nss\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_svc_empty =
"[sssd]\n\
services =\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_svc_missing =
"[sssd]\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_dom_empty =
"[sssd]\n\
services = nss, pam\n\
domains =\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_dom_missing =
"[sssd]\n\
services = nss, pam\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *test_dom_two =
"[sssd]\n\
services = nss, pam\n\
domains = LDAP, IPA\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

/* expected */

const char *exp_debug_level_exist =
"[sssd]\n\
services = nss, pam\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0330\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_debug_level_notexist =
"[sssd]\n\
services = nss, pam\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n\
[nss]\n\
debug_level=0x0330\n";

const char *exp_svc =
"[sssd]\n\
services = nss, pam, pac\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_empty =
"[sssd]\n\
services =pac\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_missing =
"[sssd]\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
services=pac\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_disable =
"[sssd]\n\
services = pam\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_disable_one =
"[sssd]\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_disable_empty =
"[sssd]\n\
services =\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_svc_disable_missing =
"[sssd]\n\
domains = LDAP\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom =
"[sssd]\n\
services = nss, pam\n\
domains = LDAP, IPA\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom_empty =
"[sssd]\n\
services = nss, pam\n\
domains =IPA\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom_missing =
"[sssd]\n\
services = nss, pam\n\
debug_level = 0x0ff0\n\
domains=IPA\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom_disable =
"[sssd]\n\
services = nss, pam\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom_disable_two =
"[sssd]\n\
services = nss, pam\n\
domains = IPA\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

const char *exp_dom_disable_empty =
"[sssd]\n\
services = nss, pam\n\
domains =\n\
debug_level = 0x0ff0\n\
[domain/LDAP]\n\
debug_level = 0x0ff0\n\
[domain/IPA]\n\
debug_level = 0x0ff0\n";

struct sss_config_ctx *config_ctx;

static bool
check_file_content(const char *filename, const char *expected)
{
    FILE *file = NULL;
    size_t i;
    int c;
    bool result;

    file = fopen(filename, "r");
    fail_if(file == NULL, "unable to open test file");

    i = 0;
    while ((c = fgetc(file)) != EOF) {
        if (c != expected[i]) {
            printf("\nnot match: %d %c == %d %c\n", c, c, expected[i], expected[i]);
            result = false;
            goto done;
        }

        i++;
    }

    if (expected[i] != '\0') {
        printf("\nnot end: %d %c == %d %c\n", c, c, expected[i], expected[i]);
        result = false;
        goto done;
    }

    result = true;

done:
    fclose(file);
    return result;
}

static void test_setup(const char *configuration)
{
    FILE *file = NULL;
    size_t ret;

    file = fopen(TEST_FILE, "w+");
    fail_if(file == NULL, "unable to create test file");

    ret = fputs(configuration, file);
    fail_if(ret == EOF, "unable to write test file");

    fail_if(fclose(file) != 0, "unable to close test file");

    config_ctx = sss_config_open(NULL, TEST_DIR, TEST_FILE);
    fail_if(config_ctx == NULL, "config_ctx is NULL");
}

static void setup(void)
{
    errno_t ret;

    ret = mkdir(TEST_SUBDIR, S_IRWXU);
    if (ret != EOK) {
        ret = errno;
        fail("unable to create test dir [%d]: %s", ret, strerror(ret));
    }

    ck_leak_check_setup();
}

static void teardown(void)
{
    errno_t ret;

    sss_config_close(&config_ctx);
    fail_if(config_ctx != NULL, "config_ctx is not NULL");

    unlink(TEST_FILE);
    unlink(TEST_FILE_BACKUP);

    ret = rmdir(TEST_SUBDIR);
    if (ret != EOK) {
        ret = errno;
        fail("unable to remove test dir [%d]: %s", ret, strerror(ret));
    }

    ck_leak_check_teardown();
}

START_TEST(test_sss_config_set_debug_level_exist)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_set_debug_level(config_ctx, "domain/LDAP", 0x0330);
    fail_if(ret != EOK, "unable change configuration");

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration");

    result = check_file_content(TEST_FILE, exp_debug_level_exist);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_set_debug_level_notexist)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_set_debug_level(config_ctx, "nss", 0x0330);
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_debug_level_notexist);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_enabled)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_service_is_enabled(config_ctx, "nss", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == false, "wrong result");
}
END_TEST

START_TEST(test_sss_config_service_disabled)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_service_is_enabled(config_ctx, "pac", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_service_disabled_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_empty);

    ret = sss_config_service_is_enabled(config_ctx, "pac", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_service_disabled_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_missing);

    ret = sss_config_service_is_enabled(config_ctx, "pac", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_service_enable)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_service_enable(config_ctx, "pac");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_enable_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_empty);

    ret = sss_config_service_enable(config_ctx, "pac");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_empty);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_svc_empty);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_enable_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_missing);

    ret = sss_config_service_enable(config_ctx, "pac");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_missing);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_svc_missing);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_disable)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_service_disable(config_ctx, "nss");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_disable);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_disable_one)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_one);

    ret = sss_config_service_disable(config_ctx, "nss");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_disable_one);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_svc_one);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_service_disable_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_empty);

    ret = sss_config_service_disable(config_ctx, "nss");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_disable_empty);
    fail_if(result == false, "file does not match");

    /* no backup file created */
}
END_TEST

START_TEST(test_sss_config_service_disable_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_svc_missing);

    ret = sss_config_service_disable(config_ctx, "nss");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_svc_disable_missing);
    fail_if(result == false, "file does not match");

    /* no backup file created */
}
END_TEST

START_TEST(test_sss_config_domain_enabled)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_domain_is_enabled(config_ctx, "LDAP", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == false, "wrong result");
}
END_TEST

START_TEST(test_sss_config_domain_disabled)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_domain_is_enabled(config_ctx, "AD", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_domain_disabled_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_empty);

    ret = sss_config_domain_is_enabled(config_ctx, "LDAP", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_domain_disabled_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_missing);

    ret = sss_config_domain_is_enabled(config_ctx, "LDAP", &result);
    fail_if(ret != EOK, "unable to read configuration [%d]: %s",
                        ret, strerror(ret));

    fail_if(result == true, "wrong result");
}
END_TEST

START_TEST(test_sss_config_domain_enable)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_domain_enable(config_ctx, "IPA");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_domain_enable_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_empty);

    ret = sss_config_domain_enable(config_ctx, "IPA");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_empty);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_dom_empty);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_domain_enable_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_missing);

    ret = sss_config_domain_enable(config_ctx, "IPA");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_missing);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_dom_missing);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_domain_disable)
{
    errno_t ret;
    bool result;

    test_setup(test_orig);

    ret = sss_config_domain_disable(config_ctx, "LDAP");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_disable);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_orig);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_domain_disable_two)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_two);

    ret = sss_config_domain_disable(config_ctx, "LDAP");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_disable_two);
    fail_if(result == false, "file does not match");

    result = check_file_content(TEST_FILE_BACKUP, test_dom_two);
    fail_if(result == false, "backup file does not match");
}
END_TEST

START_TEST(test_sss_config_domain_disable_empty)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_empty);

    ret = sss_config_domain_disable(config_ctx, "LDAP");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_disable_empty);
    fail_if(result == false, "file does not match");

    /* no backup file created */
}
END_TEST

START_TEST(test_sss_config_domain_disable_missing)
{
    errno_t ret;
    bool result;

    test_setup(test_dom_missing);

    ret = sss_config_domain_disable(config_ctx, "LDAP");
    fail_if(ret != EOK, "unable change configuration [%d]: %s",
                        ret, strerror(ret));

    ret = sss_config_save(config_ctx);
    fail_if(ret != EOK, "unable save configuration [%d]: %s",
                        ret, strerror(ret));

    result = check_file_content(TEST_FILE, exp_dom_disable);
    fail_if(result == false, "file does not match");

    /* no backup file created */
}
END_TEST

Suite *sss_config_suite(void)
{
    Suite *s = suite_create("sss_config");
    TCase *tc = tcase_create("sss_config");

    tcase_add_checked_fixture(tc, setup, teardown);

    tcase_add_test(tc, test_sss_config_set_debug_level_exist);
    tcase_add_test(tc, test_sss_config_set_debug_level_notexist);
    tcase_add_test(tc, test_sss_config_service_enabled);
    tcase_add_test(tc, test_sss_config_service_disabled);
    tcase_add_test(tc, test_sss_config_service_disabled_empty);
    tcase_add_test(tc, test_sss_config_service_disabled_missing);
    tcase_add_test(tc, test_sss_config_service_enable);
    tcase_add_test(tc, test_sss_config_service_enable_empty);
    tcase_add_test(tc, test_sss_config_service_enable_missing);
    tcase_add_test(tc, test_sss_config_service_disable);
    tcase_add_test(tc, test_sss_config_service_disable_one);
    tcase_add_test(tc, test_sss_config_service_disable_empty);
    tcase_add_test(tc, test_sss_config_service_disable_missing);
    tcase_add_test(tc, test_sss_config_domain_enabled);
    tcase_add_test(tc, test_sss_config_domain_disabled);
    tcase_add_test(tc, test_sss_config_domain_disabled_empty);
    tcase_add_test(tc, test_sss_config_domain_disabled_missing);
    tcase_add_test(tc, test_sss_config_domain_enable);
    tcase_add_test(tc, test_sss_config_domain_enable_empty);
    tcase_add_test(tc, test_sss_config_domain_enable_missing);
    tcase_add_test(tc, test_sss_config_domain_disable);
    tcase_add_test(tc, test_sss_config_domain_disable_two);
    tcase_add_test(tc, test_sss_config_domain_disable_empty);
    tcase_add_test(tc, test_sss_config_domain_disable_missing);



    tcase_set_timeout(tc, 60);

    suite_add_tcase(s, tc);

    return s;
}

int main(int argc, const char *argv[])
{
    int number_failed;

    tests_set_cwd();

    Suite *s = sss_config_suite();
    SRunner *sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    if (number_failed == 0) {
        return EXIT_SUCCESS;
    }

    return EXIT_FAILURE;
}
