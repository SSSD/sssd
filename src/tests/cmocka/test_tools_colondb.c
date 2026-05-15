/*
    Authors:
        Petr Čech <pcech@redhat.com>

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

#include <talloc.h>
#include <errno.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "src/tools/common/sss_colondb.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TESTS_FILE "test_colondb.ldb"

const char *TEST_STRING1 = "white";
const int TEST_INT1 = 12;

const char *TEST_STRING2 = "black";
const int TEST_INT2 = 34;

static void create_dir(const char *path)
{
    errno_t ret;

    errno = 0;
    ret = mkdir(path, 0775);
    assert_return_code(ret, errno);
}

static void create_empty_file(TALLOC_CTX *test_ctx, const char *path,
                              const char *name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    char *file_name = NULL;
    FILE *fp = NULL;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    create_dir(path);

    file_name = talloc_asprintf(tmp_ctx, "%s/%s", path, name);
    assert_non_null(file_name);

    fp = fopen(file_name, "w");
    assert_non_null(fp);
    fclose(fp);

    talloc_free(tmp_ctx);
}

static void create_nonempty_file(TALLOC_CTX *test_ctx,
                                 const char *path, const char *name)
{
    TALLOC_CTX *tmp_ctx = NULL;
    struct sss_colondb *db = NULL;
    errno_t ret;
    struct sss_colondb_write_field table[] = {
        { SSS_COLONDB_STRING, { .str = TEST_STRING2 } },
        { SSS_COLONDB_UINT32, { .uint32 = TEST_INT2 } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    create_empty_file(test_ctx, TESTS_PATH, TESTS_FILE);

    db = sss_colondb_open(tmp_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_writeline(db, table);
    assert_int_equal(ret, EOK);

    talloc_free(db);
    talloc_free(tmp_ctx);
}

static int setup(void **state, int file_state)
{
    TALLOC_CTX *test_ctx = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_new(global_talloc_context);
    assert_non_null(test_ctx);

    switch (file_state) {
    case 0:
        break;
    case 1:
        create_empty_file(test_ctx, TESTS_PATH, TESTS_FILE);
        break;
    case 2:
        create_nonempty_file(test_ctx, TESTS_PATH, TESTS_FILE);
        break;
    default:
        break;
    }

    check_leaks_push(test_ctx);
    *state = test_ctx;

    return 0;
}

static int without_file_setup(void **state)
{
    return setup(state, 0);
}

static int with_empty_file_setup(void **state)
{
    return setup(state, 1);
}

static int with_nonempty_file_setup(void **state)
{
    return setup(state, 2);
}

static int teardown(void **state)
{
    errno_t ret;

    errno = 0;
    ret = unlink(TESTS_PATH "/" TESTS_FILE);
    if (ret != 0) {
        assert_int_equal(errno, ENOENT);
    }

    assert_true(check_leaks_pop(*state));
    talloc_zfree(*state);

    test_dom_suite_cleanup(TESTS_PATH, NULL, NULL);
    assert_true(leak_check_teardown());

    return 0;
}

void test_open_nonexist_for_read(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_null(db);
    talloc_free(db);
}

void test_open_nonexist_for_write(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_null(db);
    talloc_free(db);
}

void test_open_exist_for_read(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);
    talloc_free(db);
}

void test_open_exist_for_write(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);
    talloc_free(db);
}

void test_open_nonempty_for_read(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);
    talloc_free(db);
}

void test_open_nonempty_for_write(void **state)
{

    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);
    talloc_free(db);
}

void test_write_to_empty(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;
    struct sss_colondb_write_field table[] = {
        { SSS_COLONDB_STRING, { .str = TEST_STRING1 } },
        { SSS_COLONDB_UINT32, { .uint32 = TEST_INT1 } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };
    errno_t ret;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_writeline(db, table);
    assert_int_equal(ret, 0);

    talloc_free(db);
}

void test_write_to_nonempty(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;
    struct sss_colondb_write_field table[] = {
        { SSS_COLONDB_STRING, { .str = TEST_STRING1 } },
        { SSS_COLONDB_UINT32, { .uint32 = TEST_INT1 } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };
    errno_t ret;

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_writeline(db, table);
    assert_int_equal(ret, 0);

    talloc_free(db);
}

void test_read_from_nonempty(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;
    errno_t ret;
    const char *string = NULL;
    uint32_t number;
    struct sss_colondb_read_field table[] = {
        { SSS_COLONDB_STRING, { .str = &string } },
        { SSS_COLONDB_UINT32, { .uint32 = &number } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_readline(test_ctx, db, table);
    assert_int_equal(ret, 0);
    assert_string_equal(string, TEST_STRING2);
    assert_int_equal(number, TEST_INT2);

    talloc_zfree(string);
    talloc_free(db);
}

void test_read_from_empty(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;
    errno_t ret;
    const char *string;
    uint32_t number;
    struct sss_colondb_read_field table[] = {
        { SSS_COLONDB_STRING, { .str = &string } },
        { SSS_COLONDB_UINT32, { .uint32 = &number } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_readline(test_ctx, db, table);
    assert_int_equal(ret, EOF);

    talloc_free(db);
}

void test_write_read(void **state)
{
    TALLOC_CTX *test_ctx = *state;
    struct sss_colondb *db = NULL;
    errno_t ret;
    const char *string = NULL;
    uint32_t number;
    struct sss_colondb_write_field table_in[] = {
        { SSS_COLONDB_STRING, { .str = TEST_STRING2 } },
        { SSS_COLONDB_UINT32, { .uint32 = TEST_INT2 } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };
    struct sss_colondb_read_field table_out[] = {
        { SSS_COLONDB_STRING, { .str = &string } },
        { SSS_COLONDB_UINT32, { .uint32 = &number } },
        { SSS_COLONDB_SENTINEL, { 0 } }
    };

    db = sss_colondb_open(test_ctx, SSS_COLONDB_WRITE,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_writeline(db, table_in);
    assert_int_equal(ret, 0);

    talloc_free(db);

    db = sss_colondb_open(test_ctx, SSS_COLONDB_READ,
                          TESTS_PATH "/" TESTS_FILE);
    assert_non_null(db);

    ret = sss_colondb_readline(test_ctx, db, table_out);
    assert_int_equal(ret, 0);
    assert_string_equal(string, TEST_STRING2);
    assert_int_equal(number, TEST_INT2);

    talloc_zfree(string);
    talloc_free(db);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_open_nonexist_for_read,
                                        without_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_open_nonexist_for_write,
                                        without_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_open_exist_for_read,
                                        with_empty_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_open_exist_for_write,
                                        with_empty_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_open_nonempty_for_read,
                                        with_nonempty_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_open_nonempty_for_write,
                                        with_nonempty_file_setup, teardown),

        cmocka_unit_test_setup_teardown(test_write_to_empty,
                                        with_empty_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_write_to_nonempty,
                                        with_nonempty_file_setup, teardown),

        cmocka_unit_test_setup_teardown(test_read_from_empty,
                                        with_empty_file_setup, teardown),
        cmocka_unit_test_setup_teardown(test_read_from_nonempty,
                                        with_nonempty_file_setup, teardown),

        cmocka_unit_test_setup_teardown(test_write_read,
                                        with_empty_file_setup, teardown),
    };

    /* Set debug level to invalid value so we can decide if -d 0 was used. */
    debug_level = SSSDBG_INVALID;

    pc = poptGetContext(argv[0], argc, argv, long_options, 0);
    while ((opt = poptGetNextOpt(pc)) != -1) {
        switch (opt) {
        default:
            fprintf(stderr, "\nInvalid option %s: %s\n\n", poptBadOption(pc, 0),
                    poptStrerror(opt));
            poptPrintUsage(pc, stderr, 0);
            return 1;
        }
    }
    poptFreeContext(pc);

    DEBUG_CLI_INIT(debug_level);

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, NULL, NULL);

    return cmocka_run_group_tests(tests, NULL, NULL);
}
