/*
    SSSD

    test_iobuf - IO buffer tests

    Copyright (C) 2016 Red Hat

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
#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>

#include "util/sss_iobuf.h"
#include "util/util.h"

static void test_sss_iobuf_read(void **state)
{
    errno_t ret;
    uint8_t buffer[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0 };
    uint8_t readbuf[64] = { 0 };
    size_t nread;
    struct sss_iobuf *rb;

    rb = sss_iobuf_init_readonly(NULL, buffer, sizeof(buffer));
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, 5, readbuf, &nread);
    assert_int_equal(ret, EOK);
    /* There is enough data in the buffer */
    assert_int_equal(nread, 5);
    /* The data matches beginning of the buffer */
    assert_int_equal(strncmp((const char *) readbuf, "Hello", 5), 0);

    memset(readbuf, 0, sizeof(readbuf));
    ret = sss_iobuf_read(rb, 3, readbuf, &nread);
    assert_int_equal(ret, EOK);
    /* There is enough data in the buffer */
    assert_int_equal(nread, 3);
    /* The data matches beginning of the buffer */
    assert_int_equal(strncmp((const char *) readbuf, " wo", 3), 0);

    /* Try to read more than the buffer has */
    memset(readbuf, 0, sizeof(readbuf));
    ret = sss_iobuf_read(rb, 10, readbuf, &nread);
    /* This is not a fatal error */
    assert_int_equal(ret, EOK);
    /* We just see how much there was */
    assert_int_equal(nread, 4);
    /* And get the rest of the buffer back. readbuf includes trailing zero now */
    assert_int_equal(strcmp((const char *) readbuf, "rld"), 0);

    /* Reading a depleted buffer will just yield zero bytes read now */
    ret = sss_iobuf_read(rb, 10, readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, 0);

    /* Failure cases */
    ret = sss_iobuf_read(NULL, 10, readbuf, &nread);
    assert_int_equal(ret, EINVAL);
    ret = sss_iobuf_read(rb, 10, NULL, &nread);
    assert_int_equal(ret, EINVAL);

    talloc_free(rb);
}

static void test_sss_iobuf_write(void **state)
{
    struct sss_iobuf *wb;
    struct sss_iobuf *rb;
    size_t hwlen = sizeof("Hello world"); /* Includes trailing zero */
    uint8_t readbuf[64];
    size_t nread;
    errno_t ret;

    /* Exactly fill the capacity */
    wb = sss_iobuf_init_empty(NULL, hwlen, hwlen);
    assert_non_null(wb);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello world"),
                              sizeof("Hello world"));
    assert_int_equal(ret, EOK);

    rb = sss_iobuf_init_readonly(NULL,
                                 sss_iobuf_get_data(wb),
                                 sss_iobuf_get_len(wb));
    talloc_free(wb);
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, sizeof(readbuf), readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, hwlen);
    assert_int_equal(strcmp((const char *) readbuf, "Hello world"), 0);
    talloc_zfree(rb);

    /* Overflow the capacity by one */
    wb = sss_iobuf_init_empty(NULL, hwlen, hwlen);
    assert_non_null(wb);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello world!"),
                              sizeof("Hello world!"));
    assert_int_not_equal(ret, EOK);
    talloc_zfree(wb);

    /* Test resizing exactly up to capacity in several writes */
    wb = sss_iobuf_init_empty(NULL, 2, hwlen);
    assert_non_null(wb);

    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello "),
                              sizeof("Hello ")-1); /* Not the null byte now.. */
    assert_int_equal(ret, EOK);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("world"),
                              sizeof("world"));
    assert_int_equal(ret, EOK);

    rb = sss_iobuf_init_readonly(NULL,
                                 sss_iobuf_get_data(wb),
                                 sss_iobuf_get_len(wb));
    talloc_free(wb);
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, sizeof(readbuf), readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, hwlen);
    assert_int_equal(strcmp((const char *) readbuf, "Hello world"), 0);
    talloc_zfree(rb);

    /* Overflow the capacity during a resize by one */
    wb = sss_iobuf_init_empty(NULL, 2, hwlen);
    assert_non_null(wb);

    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello "),
                              sizeof("Hello ")-1); /* Not the null byte now.. */
    assert_int_equal(ret, EOK);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("world!"),
                              sizeof("world!"));
    assert_int_not_equal(ret, EOK);
    talloc_zfree(wb);

    /* Test allocating an unlimited buffer */
    wb = sss_iobuf_init_empty(NULL, 2, 0);
    assert_non_null(wb);

    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello "),
                              sizeof("Hello ")-1); /* Not the null byte now.. */
    assert_int_equal(ret, EOK);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("world"),
                              sizeof("world"));
    assert_int_equal(ret, EOK);

    rb = sss_iobuf_init_readonly(NULL,
                                 sss_iobuf_get_data(wb),
                                 sss_iobuf_get_len(wb));
    talloc_free(wb);
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, sizeof(readbuf), readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, hwlen);
    assert_int_equal(strcmp((const char *) readbuf, "Hello world"), 0);
    talloc_zfree(rb);
}

int main(void)
{
    const struct CMUnitTest tests[] = {
        cmocka_unit_test(test_sss_iobuf_read),
        cmocka_unit_test(test_sss_iobuf_write),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
