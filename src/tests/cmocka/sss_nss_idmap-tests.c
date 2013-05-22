/*
    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2013 Red Hat

    Test for the NSS Responder ID-SID mapping interface

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


#include "util/util.h"

#include "sss_client/idmap/sss_nss_idmap.h"
#include "tests/cmocka/common_mock.h"

#include <nss.h>
#include "sss_client/sss_cli.h"

struct sss_nss_make_request_test_data {
    uint8_t *repbuf;
    size_t replen;
    int errnop;
    enum nss_status nss_status;
};

uint8_t buf1[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't', 0x00};
uint8_t buf2[] = {0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't', 0x00};
uint8_t buf3[] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't', 0x00};
uint8_t buf4[] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 't', 'e', 's', 't', 'x'};
enum nss_status sss_nss_make_request(enum sss_cli_command cmd,
                      struct sss_cli_req_data *rd,
                      uint8_t **repbuf, size_t *replen,
                      int *errnop)
{
    struct sss_nss_make_request_test_data *d;

    d = sss_mock_ptr_type(struct sss_nss_make_request_test_data *);

    *replen = d->replen;
    *errnop = d->errnop;

    /* the caller must be able to free repbuf. */
    if (*replen != 0 &&  d->repbuf != NULL) {
        *repbuf = malloc(*replen);
        assert_non_null(*repbuf);
        memcpy(*repbuf, d->repbuf, *replen);
    }

    return d->nss_status;
}

void test_getsidbyname(void **state) {
    int ret;
    char *sid;
    size_t c;
    enum sss_id_type type;

    struct test_data {
        struct sss_nss_make_request_test_data d;
        int ret;
        const char *str;
    } d[] = {
        {{buf1, sizeof(buf1), 0, NSS_STATUS_SUCCESS}, EOK, "test"},
        {{buf2, sizeof(buf2), 0, NSS_STATUS_SUCCESS}, EBADMSG, NULL},
        {{buf3, sizeof(buf3), 0, NSS_STATUS_SUCCESS}, ENOENT, NULL},
        {{buf4, sizeof(buf4), 0, NSS_STATUS_SUCCESS}, EBADMSG, NULL},
        {{NULL, 0, 0, 0}, 0, NULL}
    };

    ret = sss_nss_getsidbyname(NULL, NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_nss_getsidbyname("", NULL, NULL);
    assert_int_equal(ret, EINVAL);

    ret = sss_nss_getsidbyname("", &sid, NULL);
    assert_int_equal(ret, EINVAL);

    for (c = 0; d[c].d.repbuf != NULL; c++) {
        will_return(sss_nss_make_request, &d[0].d);

        ret = sss_nss_getsidbyname("test", &sid, &type);
        assert_int_equal(ret, d[0].ret);
        if (ret == EOK) {
            assert_string_equal(sid, d[0].str);
            assert_int_equal(type, 0);
        }
    }
}

int main(int argc, const char *argv[])
{

    const UnitTest tests[] = {
        unit_test(test_getsidbyname),
    };

    return run_tests(tests);
}
