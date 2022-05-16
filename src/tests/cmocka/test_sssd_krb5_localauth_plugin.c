/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2017 Red Hat

    Test for the MIT Kerberos localauth plugin

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

#include <errno.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <stdbool.h>
#include <nss.h>
#include <sys/types.h>
#include <pwd.h>

#include <krb5/krb5.h>
#include <krb5/localauth_plugin.h>

#include "tests/cmocka/common_mock.h"

struct _nss_sss_getpwnam_r_test_data {
    uid_t uid;
    const char *name;
    enum nss_status status;
};

enum nss_status _nss_sss_getpwnam_r(const char *name, struct passwd *result,
                                    char *buffer, size_t buflen, int *errnop)
{
    struct _nss_sss_getpwnam_r_test_data *test_data;

    assert_non_null(name);
    assert_non_null(result);
    assert_non_null(buffer);
    assert_int_not_equal(buflen, 0);
    assert_non_null(errnop);

    test_data = sss_mock_ptr_type(struct _nss_sss_getpwnam_r_test_data *);

    result->pw_uid = test_data->uid;
    if (test_data->name != NULL) {
        assert_true(buflen > strlen(test_data->name));
        strncpy(buffer, test_data->name, buflen);
        result->pw_name = buffer;
    }

    return test_data->status;
}

int getpwnam_r(const char *name, struct passwd *pwd,
               char *buffer, size_t buflen, struct passwd **result)
{
    struct _nss_sss_getpwnam_r_test_data *test_data;

    assert_non_null(name);
    assert_non_null(pwd);
    assert_non_null(result);
    assert_non_null(buffer);
    assert_int_not_equal(buflen, 0);

    test_data = sss_mock_ptr_type(struct _nss_sss_getpwnam_r_test_data *);

    if (test_data->status != NSS_STATUS_SUCCESS) {
        *result = NULL;
        return test_data->status == NSS_STATUS_NOTFOUND ? ENOENT : EIO;
    }

    pwd->pw_uid = test_data->uid;
    if (test_data->name != NULL) {
        assert_true(buflen > strlen(test_data->name));
        strncpy(buffer, test_data->name, buflen);
        pwd->pw_name = buffer;
    }
    *result = pwd;

    return 0;
}


krb5_error_code
localauth_sssd_initvt(krb5_context context, int maj_ver, int min_ver,
                       krb5_plugin_vtable vtable);

void test_localauth_sssd_initvt(void **state)
{
    krb5_error_code kerr;
    struct krb5_localauth_vtable_st vtable = { 0 };

    kerr = localauth_sssd_initvt(NULL, 0, 0, (krb5_plugin_vtable) &vtable);
    assert_int_equal(kerr, KRB5_PLUGIN_VER_NOTSUPP);

    kerr = localauth_sssd_initvt(NULL, 1, 1, (krb5_plugin_vtable) &vtable);
    assert_int_equal(kerr, 0);
    assert_string_equal(vtable.name, "sssd");
    assert_null(vtable.init);
    assert_null(vtable.fini);
    assert_non_null(vtable.an2ln);
    assert_non_null(vtable.userok);
    assert_non_null(vtable.free_string);
}

void test_sss_userok(void **state)
{
    krb5_error_code kerr;
    struct krb5_localauth_vtable_st vtable = { 0 };
    krb5_context krb5_ctx;
    krb5_principal princ;
    size_t c;

    struct test_data {
        struct _nss_sss_getpwnam_r_test_data d1;
        struct _nss_sss_getpwnam_r_test_data d2;
        krb5_error_code kerr;
    } test_data[] = {
        {{ 1234, NULL, NSS_STATUS_SUCCESS},  { 1234, NULL, NSS_STATUS_SUCCESS},
                                                                             0},
        /* second _nss_sss_getpwnam_r() is never called because the first one
         * already returned an error */
        {{ 1234, NULL, NSS_STATUS_NOTFOUND}, { 0, NULL, 0},
                                                         KRB5_PLUGIN_NO_HANDLE},
        {{ 1234, NULL, NSS_STATUS_SUCCESS},  { 1234, NULL, NSS_STATUS_NOTFOUND},
                                                         KRB5_PLUGIN_NO_HANDLE},
        {{ 1234, NULL, NSS_STATUS_SUCCESS},  { 4321, NULL, NSS_STATUS_SUCCESS},
                                                         KRB5_PLUGIN_NO_HANDLE},
        /* second _nss_sss_getpwnam_r() is never called because the first one
         * already returned an error */
        {{ 1234, NULL, NSS_STATUS_UNAVAIL},  { 0, NULL, 0},
                                                         KRB5_PLUGIN_NO_HANDLE},
        {{ 1234, NULL, NSS_STATUS_SUCCESS},  { 1234, NULL, NSS_STATUS_TRYAGAIN},
                                                         KRB5_PLUGIN_NO_HANDLE},
        {{ 0, NULL, 0 },                     {0 , NULL, 0}, 0}
    };

    kerr = krb5_init_context(&krb5_ctx);
    assert_int_equal(kerr, 0);

    kerr = localauth_sssd_initvt(krb5_ctx, 1, 1, (krb5_plugin_vtable) &vtable);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(krb5_ctx, "name@REALM", &princ);
    assert_int_equal(kerr, 0);


    for (c = 0; test_data[c].d1.uid != 0; c++) {
        will_return(_nss_sss_getpwnam_r, &test_data[c].d1);
        if (test_data[c].d2.uid != 0) {
            will_return(getpwnam_r, &test_data[c].d2);
        }
        kerr = vtable.userok(krb5_ctx, NULL, princ, "name");
        assert_int_equal(kerr, test_data[c].kerr);
    }

    krb5_free_principal(krb5_ctx, princ);
    krb5_free_context(krb5_ctx);
}

void test_sss_an2ln(void **state)
{
    krb5_error_code kerr;
    struct krb5_localauth_vtable_st vtable = { 0 };
    krb5_context krb5_ctx;
    krb5_principal princ;
    size_t c;
    char *lname;

    struct test_data {
        struct _nss_sss_getpwnam_r_test_data d;
        krb5_error_code kerr;
    } test_data[] = {
        { { 0, "my_name", NSS_STATUS_SUCCESS}, 0},
        { { 0, "my_name", NSS_STATUS_NOTFOUND}, KRB5_LNAME_NOTRANS},
        { { 0, "my_name", NSS_STATUS_UNAVAIL}, EIO},
        { { 0, NULL, 0 }                     , 0}
    };

    kerr = krb5_init_context(&krb5_ctx);
    assert_int_equal(kerr, 0);

    kerr = localauth_sssd_initvt(krb5_ctx, 1, 1, (krb5_plugin_vtable) &vtable);
    assert_int_equal(kerr, 0);

    kerr = krb5_parse_name(krb5_ctx, "name@REALM", &princ);
    assert_int_equal(kerr, 0);


    for (c = 0; test_data[c].d.name != NULL; c++) {
        will_return(_nss_sss_getpwnam_r, &test_data[c].d);
        kerr = vtable.an2ln(krb5_ctx, NULL, NULL, NULL, princ, &lname);
        assert_int_equal(kerr, test_data[c].kerr);
        if (kerr == 0) {
            assert_string_equal(lname, test_data[c].d.name);
            vtable.free_string(krb5_ctx, NULL, lname);
        }
    }

    krb5_free_principal(krb5_ctx, princ);
    krb5_free_context(krb5_ctx);
}

int main(int argc, const char *argv[])
{

    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_localauth_sssd_initvt),
        cmocka_unit_test(test_sss_userok),
        cmocka_unit_test(test_sss_an2ln),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
