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

#ifndef __COMMON_MOCK_KRB5_H_
#define __COMMON_MOCK_KRB5_H_

#include "util/sss_krb5.h"
#include "tests/cmocka/common_mock.h"

void mock_krb5_keytab_entry(krb5_keytab_entry *kent,
                            krb5_principal principal,
                            krb5_timestamp timestamp,
                            krb5_kvno vno,
                            krb5_enctype enctype,
                            const char *key);

int mock_keytab(krb5_context kctx,
                const char *kt_path,
                krb5_keytab_entry *kt_keys,
                size_t nkeys);

/* Dummy keys with user-selected principal */
int mock_keytab_with_contents(TALLOC_CTX *mem_ctx,
                              const char *keytab_path,
                              const char *keytab_princ);

#endif /* __COMMON_MOCK_KRB5_H_ */
