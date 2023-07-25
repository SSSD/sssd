/*
    SSSD

    sysdb_utils - Tests for various sysdb calls

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include <popt.h>

#include "tests/cmocka/common_mock.h"

#define IPA_UUID "bcae7c40-97eb-11e4-88ca-525400e96a6b"

#define AD_GUID_BIN {0x8d, 0x0d, 0xa8, 0xfe, 0xd5, 0xdb, 0x84, 0x4f, \
                     0x85, 0x74, 0x7d, 0xb0, 0x47, 0x7f, 0x96, 0x2e};
#define AD_GUID "fea80d8d-dbd5-4f84-8574-7db0477f962e"
static void test_sysdb_handle_original_uuid(void **state)
{
    int ret;
    struct sysdb_attrs *src_attrs;
    struct sysdb_attrs *dest_attrs;
    const char *guid;
    uint8_t bin_guid[] = AD_GUID_BIN;
    struct ldb_val guid_val = {bin_guid, 16};

    ret = sysdb_handle_original_uuid(NULL, NULL, NULL, NULL, NULL);
    assert_int_equal(ret, ENOENT);

    src_attrs = sysdb_new_attrs(NULL);
    assert_non_null(src_attrs);

    dest_attrs = sysdb_new_attrs(NULL);
    assert_non_null(dest_attrs);

    ret = sysdb_handle_original_uuid("xyz", src_attrs, "abc", dest_attrs,
                                     "def");
    assert_int_equal(ret, ENOENT);

    ret = sysdb_attrs_add_val(src_attrs, "GUID", &guid_val);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_string(src_attrs, "UUID", IPA_UUID);
    assert_int_equal(ret, EOK);

    ret = sysdb_handle_original_uuid(NULL, src_attrs, "GUID",
                                     dest_attrs, "def");
    assert_int_equal(ret, ENOENT);

    ret = sysdb_handle_original_uuid("objectGUID", NULL, "GUID",
                                     dest_attrs, "def");
    assert_int_equal(ret, EINVAL);

    ret = sysdb_handle_original_uuid("objectGUID", src_attrs, "GUID",
                                     dest_attrs, "def");
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_get_string(dest_attrs, "def", &guid);
    assert_int_equal(ret, EOK);
    assert_string_equal(guid, AD_GUID);

    ret = sysdb_handle_original_uuid("ipaUniqueID", src_attrs, "UUID",
                                     dest_attrs, "ghi");
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_get_string(dest_attrs, "ghi", &guid);
    assert_int_equal(ret, EOK);
    assert_string_equal(guid, IPA_UUID);

    talloc_free(src_attrs);
    src_attrs = sysdb_new_attrs(NULL);
    assert_non_null(src_attrs);

    /* check objectGUID with length other than 16 */
    ret = sysdb_attrs_add_string(src_attrs, "GUID", IPA_UUID);
    assert_int_equal(ret, EOK);
    ret = sysdb_handle_original_uuid("objectGUID", src_attrs, "GUID",
                                     dest_attrs, "jkl");
    assert_int_equal(ret, EOK);
    ret = sysdb_attrs_get_string(dest_attrs, "jkl", &guid);
    assert_int_equal(ret, EOK);
    assert_string_equal(guid, IPA_UUID);

    talloc_free(src_attrs);
    talloc_free(dest_attrs);
}

#define TEST_BASE64_ABC "YWJj"
#define TEST_BASE64_123 "AQID"
static void test_sysdb_attrs_add_base64_blob(void **state)
{
    struct sysdb_attrs *attrs;
    struct ldb_message_element *el;
    char zero[] = { '\1', '\2', '\3' };
    int ret;

    attrs = sysdb_new_attrs(NULL);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_base64_blob(attrs, "testAttrABC", TEST_BASE64_ABC);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_base64_blob(attrs, "testAttr000", TEST_BASE64_123);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_get_el(attrs, "testAttrABC", &el);
    assert_int_equal(ret, EOK);
    assert_int_equal(el->num_values, 1);
    assert_non_null(el->values);
    assert_non_null(el->values[0].data);
    assert_int_equal(el->values[0].length, 3);
    assert_memory_equal(el->values[0].data, "abc", 3);

    ret = sysdb_attrs_get_el(attrs, "testAttr000", &el);
    assert_int_equal(ret, EOK);
    assert_int_equal(el->num_values, 1);
    assert_non_null(el->values);
    assert_non_null(el->values[0].data);
    assert_int_equal(el->values[0].length, 3);
    assert_memory_equal(el->values[0].data, zero, 3);
}

void test_sysdb_cert_derb64_to_ldap_filter(void **state)
{
    int ret;
    char *filter;

    ret = sysdb_cert_derb64_to_ldap_filter(NULL, NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sysdb_cert_derb64_to_ldap_filter(NULL, "AAECAwQFBgcICQ==", "attrName",
                                           &filter);
    assert_int_equal(ret, EOK);
    assert_string_equal(filter,
                        "(attrName=\\00\\01\\02\\03\\04\\05\\06\\07\\08\\09)");

    talloc_free(filter);
}


int main(int argc, const char *argv[])
{
    int rv;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sysdb_handle_original_uuid),
        cmocka_unit_test(test_sysdb_attrs_add_base64_blob),
        cmocka_unit_test(test_sysdb_cert_derb64_to_ldap_filter),
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
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
