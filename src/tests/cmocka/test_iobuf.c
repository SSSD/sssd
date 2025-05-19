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
#define _GNU_SOURCE                /* For memmem() */

#include "config.h"

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <malloc.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#ifdef HAVE_VALGRIND_VALGRIND_H
#include <valgrind/valgrind.h>
#endif
#include <cmocka.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util/sss_iobuf.h"
#include "util/util.h"
#include "tests/common.h"


static int test_sss_iobuf_secure_setup(void **state)
{
    int res = 0;

    /*
     * Avoid using mmap(2) for the memory allocations.
     * Although these two options seem to be redundant, if one of them
     * is missing the test fails on certains platforms.
     * Using the maximum threshold (4 * 1024 * 1024 * sizeof(long)) also
     * make the test fail.
     */
    res += mallopt(M_MMAP_THRESHOLD, 3 * 1024 * 1024 * sizeof(long));
    res += mallopt(M_MMAP_MAX, 0);

    return (res == 2 ? 0 : -1);
}

static int test_sss_iobuf_secure_teardown(void **state)
{
    unlink("./heap.bin.0");
    unlink("./heap.bin.1");
    unlink("./heap.bin.2");
    unlink("./heap.bin.3");
    unlink("./heap.bin.4");
    unlink("./heap.bin.5");

    return 0;
}

static void check_clean(const uint8_t *data, size_t size)
{
    const uint8_t *p;

    for (p = data + size; p >= data; p--) {
        assert_int_equal(*p, 0);
    }
}

static void test_sss_iobuf_secure(void **state)
{
    static const uint8_t secret[] = "=== This is the secret to hide ===";
    static const uint8_t no_secret[] = "=== This is no secret ===";
    TALLOC_CTX *mem_ctx;
    const uint8_t *data_s;
    const uint8_t *data_ns;
    size_t size_s;
    size_t size_ns;
    struct sss_iobuf *iobuf_secret;
    struct sss_iobuf *iobuf_secret_2;
    struct sss_iobuf *iobuf_nosecret;

#ifdef HAVE_VALGRIND_VALGRIND_H
    /* Valgrind interferes with this test by somehow making disappear the heap.
     * So don't run it on Valgrind. */
    if (RUNNING_ON_VALGRIND) {
        skip();
    }
#endif

    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    iobuf_secret = sss_iobuf_init_readonly(mem_ctx, secret, sizeof(secret), true);
    assert_non_null(iobuf_secret);
    data_s = sss_iobuf_get_data(iobuf_secret);
    size_s = sss_iobuf_get_size(iobuf_secret);
    assert_int_equal(size_s, sizeof(secret));
    assert_memory_equal(data_s, secret, size_s);

    iobuf_nosecret = sss_iobuf_init_readonly(mem_ctx, no_secret, sizeof(no_secret), false);
    assert_non_null(iobuf_nosecret);
    data_ns = sss_iobuf_get_data(iobuf_nosecret);
    size_ns = sss_iobuf_get_size(iobuf_nosecret);
    assert_int_equal(size_ns, sizeof(no_secret));
    assert_memory_equal(data_ns, no_secret, size_ns);

    talloc_free(iobuf_secret);
    check_clean(data_s, size_s);

    iobuf_secret = sss_iobuf_init_readonly(mem_ctx, secret, sizeof(secret), true);
    assert_non_null(iobuf_secret);
    data_s = sss_iobuf_get_data(iobuf_secret);
    size_s = sss_iobuf_get_size(iobuf_secret);

    iobuf_secret_2 = sss_iobuf_init_steal(mem_ctx, sss_iobuf_get_data(iobuf_secret),
                                          sss_iobuf_get_size(iobuf_secret), true);
    assert_non_null(iobuf_secret_2);
    data_s = sss_iobuf_get_data(iobuf_secret_2);
    size_s = sss_iobuf_get_size(iobuf_secret_2);
    assert_int_equal(size_s, sizeof(secret));
    assert_memory_equal(data_s, secret, size_s);

    talloc_free(iobuf_secret);
    assert_memory_equal(data_s, secret, size_s);

    talloc_free(mem_ctx);
    check_clean(data_s, size_s);
    assert_memory_equal(data_ns, no_secret, size_ns);
}


static void test_sss_iobuf_read(void **state)
{
    errno_t ret;
    uint8_t buffer[] = { 'H', 'e', 'l', 'l', 'o', ' ', 'w', 'o', 'r', 'l', 'd', 0 };
    uint8_t readbuf[64] = { 0 };
    size_t nread;
    struct sss_iobuf *rb;

    rb = sss_iobuf_init_readonly(NULL, buffer, sizeof(buffer), false);
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
    wb = sss_iobuf_init_empty(NULL, hwlen, hwlen, false);
    assert_non_null(wb);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello world"),
                              sizeof("Hello world"));
    assert_int_equal(ret, EOK);

    rb = sss_iobuf_init_readonly(NULL,
                                 sss_iobuf_get_data(wb),
                                 sss_iobuf_get_len(wb),
                                 false);
    talloc_free(wb);
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, sizeof(readbuf), readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, hwlen);
    assert_int_equal(strcmp((const char *) readbuf, "Hello world"), 0);
    talloc_zfree(rb);

    /* Overflow the capacity by one */
    wb = sss_iobuf_init_empty(NULL, hwlen, hwlen, false);
    assert_non_null(wb);
    ret = sss_iobuf_write_len(wb,
                              (uint8_t *) discard_const("Hello world!"),
                              sizeof("Hello world!"));
    assert_int_not_equal(ret, EOK);
    talloc_zfree(wb);

    /* Test resizing exactly up to capacity in several writes */
    wb = sss_iobuf_init_empty(NULL, 2, hwlen, false);
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
                                 sss_iobuf_get_len(wb),
                                 false);
    talloc_free(wb);
    assert_non_null(rb);

    ret = sss_iobuf_read(rb, sizeof(readbuf), readbuf, &nread);
    assert_int_equal(ret, EOK);
    assert_int_equal(nread, hwlen);
    assert_int_equal(strcmp((const char *) readbuf, "Hello world"), 0);
    talloc_zfree(rb);

    /* Overflow the capacity during a resize by one */
    wb = sss_iobuf_init_empty(NULL, 2, hwlen, false);
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
    wb = sss_iobuf_init_empty(NULL, 2, 0, false);
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
                                 sss_iobuf_get_len(wb),
                                 false);
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
        cmocka_unit_test_setup_teardown(test_sss_iobuf_secure, test_sss_iobuf_secure_setup, test_sss_iobuf_secure_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
