/*
    Authors:
        Sumit Bose <sbose@redhat.com>
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2015 Red Hat

    SSSD tests: Tests keytab utilities

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

#include "util/sss_krb5.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_krb5.h"

int mock_keytab(krb5_context kctx,
                const char *kt_path,
                krb5_keytab_entry *kt_keys,
                size_t nkeys)
{
    krb5_error_code kerr;
    krb5_keytab keytab;
    size_t n;

    kerr = krb5_kt_resolve(kctx, kt_path, &keytab);
    assert_int_equal(kerr, 0);

    for (n = 0; n < nkeys; n++) {
        kerr = krb5_kt_add_entry(kctx, keytab, &kt_keys[n]);
        assert_int_equal(kerr, 0);
    }

    kerr = krb5_kt_close(kctx, keytab);
    assert_int_equal(kerr, 0);

    return EOK;
}

void mock_krb5_keytab_entry(krb5_keytab_entry *kent,
                            krb5_principal principal,
                            krb5_timestamp timestamp,
                            krb5_kvno vno,
                            krb5_enctype enctype,
                            const char *key)
{
    memset(kent, 0, sizeof(krb5_keytab_entry));

    kent->magic = KV5M_KEYTAB_ENTRY;
    kent->principal = principal;
    kent->timestamp = timestamp;
    kent->vno = vno;
    kent->key.magic = KV5M_KEYBLOCK;
    kent->key.enctype = enctype;
    kent->key.length = strlen(key) - 1;
    kent->key.contents = (krb5_octet *) discard_const(key);
}

int mock_keytab_with_contents(TALLOC_CTX *mem_ctx,
                              const char *keytab_path,
                              const char *keytab_princ)
{
    krb5_context kctx;
    krb5_principal principal;
    krb5_error_code kerr;
    size_t nkeys = 2;
    krb5_keytab_entry keys[nkeys];
    char *keytab_file_name;

    kerr = krb5_init_context(&kctx);
    assert_int_equal(kerr, 0);

    keytab_file_name = talloc_asprintf(mem_ctx, "FILE:%s", keytab_path);
    assert_non_null(keytab_file_name);

    kerr = krb5_parse_name(kctx, keytab_princ, &principal);
    assert_int_equal(kerr, 0);

    memset(&keys, nkeys, nkeys * sizeof(krb5_keytab_entry));

    mock_krb5_keytab_entry(&keys[0], principal, 12345, 1, 1, "11");
    mock_krb5_keytab_entry(&keys[1], principal, 12345, 1, 2, "12");

    kerr = mock_keytab(kctx, keytab_file_name, keys, nkeys);
    assert_int_equal(kerr, 0);

    krb5_free_principal(kctx, principal);
    krb5_free_context(kctx);
    talloc_free(keytab_file_name);

    return 0;
}
