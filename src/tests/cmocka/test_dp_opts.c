/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2014 Red Hat

    SSSD tests: Data Provider Option Tests

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

#include <popt.h>

#include "providers/data_provider.h"

#include "tests/cmocka/common_mock.h"

#define STRING_DEFAULT  "stringval"
#define BLOB_DEFAULT    "blobval"
#define INT_DEFAULT     123

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_opt_conf.ldb"
#define TEST_DOM_NAME "opt_test"
#define TEST_ID_PROVIDER "ldap"

enum test_opts {
    OPT_STRING_NODEFAULT,
    OPT_STRING_DEFAULT,
    OPT_BLOB_NODEFAULT,
    OPT_BLOB_DEFAULT,
    OPT_INT_NODEFAULT,
    OPT_INT_DEFAULT,
    OPT_BOOL_TRUE,
    OPT_BOOL_FALSE,

    OPT_NUM_OPTS
};

struct dp_option test_def_opts[] = {
    { "string_nodefault", DP_OPT_STRING, NULL_STRING, NULL_STRING },
    { "string_default", DP_OPT_STRING, { STRING_DEFAULT }, NULL_STRING},
    { "blob_nodefault", DP_OPT_BLOB, NULL_BLOB, NULL_BLOB },
    { "blob_default", DP_OPT_BLOB,
                      { .blob = { discard_const(BLOB_DEFAULT),
                                  sizeof(BLOB_DEFAULT) - 1 } },
                      NULL_BLOB },
    { "int_nodefault", DP_OPT_NUMBER, NULL_NUMBER, NULL_NUMBER },
    { "int_default", DP_OPT_NUMBER, { .number = INT_DEFAULT }, NULL_NUMBER },
    { "bool_true", DP_OPT_BOOL, BOOL_TRUE, BOOL_TRUE },
    { "bool_false", DP_OPT_BOOL, BOOL_FALSE, BOOL_FALSE },
    DP_OPTION_TERMINATOR
};

static void assert_defaults(struct dp_option *opts)
{
    char *s;
    struct dp_opt_blob b;
    int i;
    bool bo;

    s = dp_opt_get_string(opts, OPT_STRING_NODEFAULT);
    assert_null(s);

    s = dp_opt_get_string(opts, OPT_STRING_DEFAULT);
    assert_non_null(s);
    assert_string_equal(s, STRING_DEFAULT);

    b = dp_opt_get_blob(opts, OPT_BLOB_NODEFAULT);
    assert_null(b.data);
    assert_int_equal(b.length, 0);

    b = dp_opt_get_blob(opts, OPT_BLOB_DEFAULT);
    assert_non_null(b.data);
    assert_int_equal(b.length, strlen(BLOB_DEFAULT));
    assert_memory_equal(b.data, BLOB_DEFAULT, strlen(BLOB_DEFAULT));

    i = dp_opt_get_int(opts, OPT_INT_NODEFAULT);
    assert_int_equal(i, 0);

    i = dp_opt_get_int(opts, OPT_INT_DEFAULT);
    assert_int_equal(i, INT_DEFAULT);

    bo = dp_opt_get_bool(opts, OPT_BOOL_TRUE);
    assert_true(bo == true);

    bo = dp_opt_get_bool(opts, OPT_BOOL_FALSE);
    assert_true(bo == false);
}

void opt_test_copy_default(void **state)
{
    int ret;
    TALLOC_CTX *mem_ctx;
    struct dp_option *opts;
    struct dp_opt_blob b;

    mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(mem_ctx);

    ret = dp_copy_defaults(mem_ctx, test_def_opts, OPT_NUM_OPTS, &opts);
    assert_int_equal(ret, EOK);
    assert_defaults(opts);

    /* Test that copy_defaults would still copy defaults even if we
     * change the values
     */
    ret = dp_opt_set_string(opts, OPT_STRING_NODEFAULT, "str1");
    assert_int_equal(ret, EOK);
    ret = dp_opt_set_string(opts, OPT_STRING_DEFAULT, "str2");
    assert_int_equal(ret, EOK);

    b.data = discard_const_p(uint8_t, "blob1");
    b.length = strlen("blob1");
    ret = dp_opt_set_blob(opts, OPT_BLOB_NODEFAULT, b);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_blob(opts, OPT_BLOB_DEFAULT, b);
    b.data = discard_const_p(uint8_t, "blob2");
    b.length = strlen("blob2");
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_int(opts, OPT_INT_NODEFAULT, 456);
    assert_int_equal(ret, EOK);
    ret = dp_opt_set_int(opts, OPT_INT_DEFAULT, 789);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_bool(opts, OPT_BOOL_TRUE, false);
    assert_int_equal(ret, EOK);
    ret = dp_opt_set_bool(opts, OPT_BOOL_FALSE, true);
    assert_int_equal(ret, EOK);

    talloc_free(opts);
    ret = dp_copy_defaults(mem_ctx, test_def_opts, OPT_NUM_OPTS, &opts);
    assert_int_equal(ret, EOK);
    assert_defaults(opts);
}

void opt_test_copy_options(void **state)
{
    int ret;
    TALLOC_CTX *mem_ctx;
    struct dp_option *opts;
    char *s;
    struct dp_opt_blob b;
    int i;
    bool bo;

    mem_ctx = talloc_new(global_talloc_context);
    assert_non_null(mem_ctx);

    ret = dp_copy_options(mem_ctx, test_def_opts, OPT_NUM_OPTS, &opts);
    assert_int_equal(ret, EOK);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_string(opts, OPT_STRING_NODEFAULT, "str1");
    assert_int_equal(ret, EOK);

    b.data = discard_const_p(uint8_t, "blob1");
    b.length = strlen("blob1");
    ret = dp_opt_set_blob(opts, OPT_BLOB_NODEFAULT, b);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_int(opts, OPT_INT_NODEFAULT, 456);
    assert_int_equal(ret, EOK);

    ret = dp_opt_set_bool(opts, OPT_BOOL_TRUE, false);
    assert_int_equal(ret, EOK);

    /* Test that options set to an explicit value retain
     * the value and even options with default value
     * do not return the default unless explicitly set
     */
    s = dp_opt_get_string(opts, OPT_STRING_NODEFAULT);
    assert_string_equal(s, "str1");
    s = dp_opt_get_string(opts, OPT_STRING_DEFAULT);
    assert_null(s);

    b = dp_opt_get_blob(opts, OPT_BLOB_NODEFAULT);
    assert_non_null(b.data);
    assert_int_equal(b.length, strlen("blob1"));
    assert_memory_equal(b.data, "blob1", strlen("blob1"));
    b = dp_opt_get_blob(opts, OPT_BLOB_DEFAULT);
    assert_null(b.data);
    assert_int_equal(b.length, 0);

    i = dp_opt_get_int(opts, OPT_INT_NODEFAULT);
    assert_int_equal(i, 456);
    i = dp_opt_get_int(opts, OPT_INT_DEFAULT);
    assert_int_equal(i, 0);

    bo = dp_opt_get_bool(opts, OPT_BOOL_TRUE);
    assert_false(bo == true);
}

void opt_test_get(void **state)
{
    int ret;
    struct sss_test_ctx *tctx;
    struct dp_option *opts;
    struct sss_test_conf_param params[] = {
        { "string_nodefault", "stringval2" },
        { "blob_nodefault", "blobval2" },
        { "int_nodefault", "456" },
        { "bool_true", "false" },
        { NULL, NULL },             /* Sentinel */
    };
    char *s;
    struct dp_opt_blob b;
    int i;
    bool bo;

    tctx = create_dom_test_ctx(global_talloc_context, TESTS_PATH, TEST_CONF_DB,
                               TEST_DOM_NAME, TEST_ID_PROVIDER, params);
    assert_non_null(tctx);

    ret = dp_get_options(tctx, tctx->confdb, tctx->conf_dom_path,
                         test_def_opts, OPT_NUM_OPTS, &opts);
    assert_int_equal(ret, EOK);

    /* Options that were not specified explicitly should only have the default
     * value, those that have been specified explicitly should carry that
     * value
     */
    s = dp_opt_get_string(opts, OPT_STRING_NODEFAULT);
    assert_non_null(s);
    assert_string_equal(s, "stringval2");

    s = dp_opt_get_string(opts, OPT_STRING_DEFAULT);
    assert_non_null(s);
    assert_string_equal(s, STRING_DEFAULT);

    b = dp_opt_get_blob(opts, OPT_BLOB_NODEFAULT);
    assert_non_null(b.data);
    assert_int_equal(b.length, strlen("blobval2"));
    assert_memory_equal(b.data, "blobval2", strlen("blobval2"));

    b = dp_opt_get_blob(opts, OPT_BLOB_DEFAULT);
    assert_non_null(b.data);
    assert_int_equal(b.length, strlen(BLOB_DEFAULT));
    assert_memory_equal(b.data, BLOB_DEFAULT, strlen(BLOB_DEFAULT));

    i = dp_opt_get_int(opts, OPT_INT_NODEFAULT);
    assert_int_equal(i, 456);

    i = dp_opt_get_int(opts, OPT_INT_DEFAULT);
    assert_int_equal(i, INT_DEFAULT);

    bo = dp_opt_get_bool(opts, OPT_BOOL_TRUE);
    assert_true(bo == false);

    bo = dp_opt_get_bool(opts, OPT_BOOL_FALSE);
    assert_true(bo == false);

    talloc_free(tctx);
}

static int opt_test_getset_setup(void **state)
{
    int ret;
    struct dp_option *opts;

    ret = dp_copy_defaults(global_talloc_context,
                           test_def_opts, OPT_NUM_OPTS, &opts);
    assert_int_equal(ret, EOK);
    assert_defaults(opts);

    *state = opts;
    return 0;
}

static int opt_test_getset_teardown(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);
    talloc_free(opts);
    return 0;
}

static void assert_nondefault_string_empty(struct dp_option *opts)
{
    char *s;

    s = dp_opt_get_string(opts, OPT_STRING_NODEFAULT);
    assert_null(s);
}

static void set_nondefault_string(struct dp_option *opts)
{
    int ret;

    ret = dp_opt_set_string(opts, OPT_STRING_NODEFAULT, "str1");
    assert_int_equal(ret, EOK);
}

static void check_nondefault_string(struct dp_option *opts)
{
    char *s;

    s = dp_opt_get_string(opts, OPT_STRING_NODEFAULT);
    assert_non_null(s);
    assert_string_equal(s, "str1");
}

void opt_test_getset_string(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);

    assert_nondefault_string_empty(opts);
    set_nondefault_string(opts);
    check_nondefault_string(opts);
}

static void assert_nondefault_blob_empty(struct dp_option *opts)
{
    struct dp_opt_blob b;

    b = dp_opt_get_blob(opts, OPT_BLOB_NODEFAULT);
    assert_null(b.data);
    assert_int_equal(b.length, 0);
}

static void set_nondefault_blob(struct dp_option *opts)
{
    struct dp_opt_blob b;
    int ret;

    b.data = discard_const_p(uint8_t, "blob2");
    b.length = strlen("blob2");
    ret = dp_opt_set_blob(opts, OPT_BLOB_NODEFAULT, b);
    assert_int_equal(ret, EOK);
}

static void check_nondefault_blob(struct dp_option *opts)
{
    struct dp_opt_blob b;

    b = dp_opt_get_blob(opts, OPT_BLOB_NODEFAULT);
    assert_non_null(b.data);
    assert_int_equal(b.length, strlen("blob2"));
    assert_memory_equal(b.data, "blob2", strlen("blob2"));
}

void opt_test_getset_blob(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);

    assert_nondefault_blob_empty(opts);
    set_nondefault_blob(opts);
    check_nondefault_blob(opts);
}

static void assert_nondefault_int_notset(struct dp_option *opts)
{
    int i;
    i = dp_opt_get_int(opts, OPT_INT_NODEFAULT);
    assert_int_equal(i, 0);
}

static void set_nondefault_int(struct dp_option *opts)
{
    int ret;
    ret = dp_opt_set_int(opts, OPT_INT_NODEFAULT, 456);
    assert_int_equal(ret, EOK);
}

static void assert_nondefault_int_set(struct dp_option *opts)
{
    int i;
    i = dp_opt_get_int(opts, OPT_INT_NODEFAULT);
    assert_int_equal(i, 456);
}

void opt_test_getset_int(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);

    assert_nondefault_int_notset(opts);
    set_nondefault_int(opts);
    assert_nondefault_int_set(opts);
}

void opt_test_getset_bool(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);
    int ret;
    bool b;

    b = dp_opt_get_bool(opts, OPT_BOOL_TRUE);
    assert_true(b == true);

    ret = dp_opt_set_bool(opts, OPT_BOOL_TRUE, false);
    assert_int_equal(ret, EOK);

    b = dp_opt_get_bool(opts, OPT_BOOL_TRUE);
    assert_false(b == true);
}

void opt_test_inherit(void **state)
{
    struct dp_option *opts = talloc_get_type(*state, struct dp_option);
    int ret;
    struct dp_option *opts_copy;
    const char *s;
    const char *sd_inherit_match[] = { "string_nodefault",
                                       "blob_nodefault",
                                       "int_nodefault",
                                       "bool_true",
                                       NULL };

    ret = dp_copy_defaults(opts, test_def_opts,
                           OPT_NUM_OPTS, &opts_copy);
    assert_int_equal(ret, EOK);
    assert_defaults(opts);

    dp_option_inherit_match(NULL, OPT_STRING_NODEFAULT,
                            opts, opts_copy);
    s = dp_opt_get_string(opts_copy, OPT_STRING_NODEFAULT);
    assert_null(s);

    /* string */
    assert_nondefault_string_empty(opts_copy);
    set_nondefault_string(opts);
    dp_option_inherit_match(discard_const(sd_inherit_match),
                            OPT_STRING_NODEFAULT,
                            opts, opts_copy);
    check_nondefault_string(opts_copy);

    /* blob */
    assert_nondefault_blob_empty(opts_copy);
    set_nondefault_blob(opts);
    dp_option_inherit_match(discard_const(sd_inherit_match),
                            OPT_BLOB_NODEFAULT,
                            opts, opts_copy);
    check_nondefault_blob(opts_copy);

    /* number */
    assert_nondefault_int_notset(opts_copy);
    set_nondefault_int(opts);
    dp_option_inherit_match(discard_const(sd_inherit_match),
                            OPT_INT_NODEFAULT,
                            opts, opts_copy);
    assert_nondefault_int_set(opts_copy);

    /* bool */
    assert_true(dp_opt_get_bool(opts_copy, OPT_BOOL_TRUE));

    ret = dp_opt_set_bool(opts, OPT_BOOL_TRUE, false);
    assert_int_equal(ret, EOK);

    dp_option_inherit_match(discard_const(sd_inherit_match),
                            OPT_BOOL_TRUE,
                            opts, opts_copy);

    assert_false(dp_opt_get_bool(opts_copy, OPT_BOOL_TRUE));
}

int main(int argc, const char *argv[])
{
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    int ret;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };
    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(opt_test_getset_string,
                                        opt_test_getset_setup,
                                        opt_test_getset_teardown),
        cmocka_unit_test_setup_teardown(opt_test_getset_int,
                                        opt_test_getset_setup,
                                        opt_test_getset_teardown),
        cmocka_unit_test_setup_teardown(opt_test_getset_bool,
                                        opt_test_getset_setup,
                                        opt_test_getset_teardown),
        cmocka_unit_test_setup_teardown(opt_test_getset_blob,
                                        opt_test_getset_setup,
                                        opt_test_getset_teardown),
        cmocka_unit_test_setup_teardown(opt_test_inherit,
                                        opt_test_getset_setup,
                                        opt_test_getset_teardown),
        cmocka_unit_test(opt_test_copy_default),
        cmocka_unit_test(opt_test_copy_options),
        cmocka_unit_test(opt_test_get)
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

    /* Even though normally the tests should clean up after themselves
     * they might not after a failed run. Remove the old DB to be sure */
    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    test_dom_suite_setup(TESTS_PATH);

    ret = cmocka_run_group_tests(tests, NULL, NULL);
    if (ret == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }
    return ret;
}
