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

#include <stdio.h>
#include <fcntl.h>
#include <errno.h>
#include <stdlib.h>
#include <stdarg.h>
#include <string.h>
#include <stddef.h>
#include <setjmp.h>
#include <valgrind/valgrind.h>
#include <cmocka.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include "util/sss_iobuf.h"
#include "util/util.h"
#include "tests/common.h"


static void copy_heap_to_file(int out, int in, off_t start, off_t end)
{
    static char buffer[5*1024*1024];
    off_t pos;
    ssize_t bytes_to_write;
    ssize_t bytes_written;
    size_t size = end - start;

    pos = lseek(in, start, SEEK_SET);
    assert_int_equal(pos, start);

    while (size > 0) {
        sss_erase_mem_securely(buffer, sizeof(buffer));
        bytes_to_write = read(in, buffer, MIN(size, sizeof(buffer)));
        assert_int_not_equal(bytes_to_write, -1);

        while (bytes_to_write > 0) {
            bytes_written = write(out, buffer, bytes_to_write);
            assert_int_not_equal(bytes_written, -1);

            bytes_to_write -= bytes_written;
            size -= bytes_written;
        }
    }
}

static void read_heap_to_file(const char *output)
{
#   define LINE_SIZE 1000
#   define FIELD_SIZE  20
    FILE *maps;
    int mem;
    int out;
    char line[LINE_SIZE];
    char type[FIELD_SIZE + 1];
    char start_str[FIELD_SIZE + 1];
    char end_str[FIELD_SIZE + 1];
    char *end_ptr;
    off_t start = 0;
    off_t end = 0;
    int items;


    maps = fopen("/proc/self/maps", "r");
    assert_non_null(maps);

    mem = open("/proc/self/mem", O_RDONLY);
    assert_int_not_equal(mem, -1);

    out = open(output, O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    assert_int_not_equal(out, -1);

    while (fgets(line, LINE_SIZE, maps) != NULL) {
        errno = 0;
        items = sscanf(line,
                       "%" AS_STR(FIELD_SIZE) "[0-9a-fA-F]-%" AS_STR(FIELD_SIZE)
                           "[0-9a-fA-F] %*[rwxp-] %*[0-9a-fA-F] %*d:%*d %*d %"
                           AS_STR(FIELD_SIZE) "s",
                       start_str, end_str, type);
        if (errno == 0 && items == 3 && strcmp(type, "[heap]") == 0) {
            start = strtoul(start_str, &end_ptr, 16);
            assert_int_equal(*end_ptr, '\0');
            end = strtoul(end_str, &end_ptr, 16);
            assert_int_equal(*end_ptr, '\0');

            copy_heap_to_file(out, mem, start, end);
        }
    }
    close(out);
    close(mem);
    fclose(maps);
}


static void map_file(const char *filename, void **_map, size_t *_size)
{
    int fd;
    int res;
    void *map;
    struct stat stat;


    fd = open(filename, O_RDWR);
    assert_int_not_equal(fd, -1);

    res = fstat(fd, &stat);
    assert_int_equal(res, 0);

    map = mmap(NULL, stat.st_size, PROT_READ | PROT_WRITE, MAP_PRIVATE, fd, 0);
    assert_int_not_equal(map, MAP_FAILED);

    close(fd);

    *_map = map;
    *_size = stat.st_size;
}

static void check_presence(const char *filename,
                           const uint8_t *data1, size_t size1, bool present1,
                           const uint8_t *data2, size_t size2, bool present2)
{
    void *pos;
    void *map;
    size_t map_size;

    map_file(filename, &map, &map_size);

    pos = memmem(map, map_size, data1, size1);
    if (present1) {
        assert_non_null(pos);
    } else {
        assert_null(pos);
    }

    if (data2 != NULL) {
        pos = memmem(map, map_size, data2, size2);
        if (present2) {
            assert_non_null(pos);
        } else {
            assert_null(pos);
        }
    }

    sss_erase_mem_securely(map, map_size);
    munmap(map, map_size);
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

static void test_sss_iobuf_secure(void **state)
{
    static const uint8_t secret[] = "=== This is the secret to hide ===";
    static const uint8_t no_secret[] = "=== This is no secret ===";
    TALLOC_CTX *mem_ctx;
    struct sss_iobuf *iobuf_secret;
    struct sss_iobuf *iobuf_secret_2;
    struct sss_iobuf *iobuf_nosecret;

    /* Valgrind interferes with this test by somehow making disappear the heap.
     * So don't run it on Valgrind. */
    if (RUNNING_ON_VALGRIND) {
        skip();
    }


    mem_ctx = talloc_new(NULL);
    assert_non_null(mem_ctx);

    read_heap_to_file("./heap.bin.0");

    iobuf_secret = sss_iobuf_init_readonly(mem_ctx, secret, sizeof(secret), true);
    assert_non_null(iobuf_secret);
    iobuf_nosecret = sss_iobuf_init_readonly(mem_ctx, no_secret, sizeof(no_secret), false);
    assert_non_null(iobuf_nosecret);
    read_heap_to_file("./heap.bin.1");

    talloc_free(iobuf_secret);
    read_heap_to_file("./heap.bin.2");

    iobuf_secret = sss_iobuf_init_readonly(mem_ctx, secret, sizeof(secret), true);
    assert_non_null(iobuf_secret);
    read_heap_to_file("./heap.bin.3");

    iobuf_secret_2 = sss_iobuf_init_steal(mem_ctx, sss_iobuf_get_data(iobuf_secret),
                                          sss_iobuf_get_size(iobuf_secret), true);
    assert_non_null(iobuf_secret_2);
    talloc_free(iobuf_secret);
    read_heap_to_file("./heap.bin.4");

    talloc_free(mem_ctx);
    read_heap_to_file("./heap.bin.5");

    check_presence("./heap.bin.0",
                   secret, sizeof(secret), false,
                   no_secret, sizeof(no_secret), false);
    check_presence("./heap.bin.1",
                   secret, sizeof(secret), true,
                   no_secret, sizeof(no_secret), true);
    check_presence("./heap.bin.2",
                   secret, sizeof(secret), false,
                   no_secret, sizeof(no_secret), true);
    check_presence("./heap.bin.3",
                   secret, sizeof(secret), true,
                   no_secret, sizeof(no_secret), true);
    check_presence("./heap.bin.4",
                   secret, sizeof(secret), true,
                   no_secret, sizeof(no_secret), true);
    check_presence("./heap.bin.5",
                   secret, sizeof(secret), false,
                   NULL, 0, false);
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
        cmocka_unit_test_setup_teardown(test_sss_iobuf_secure, NULL, test_sss_iobuf_secure_teardown),
    };

    return cmocka_run_group_tests(tests, NULL, NULL);
}
