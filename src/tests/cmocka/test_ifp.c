/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: InfoPipe responder

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

#include "db/sysdb.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/ifp/ifp_private.h"
#include "sbus/sssd_dbus_private.h"

/* dbus library checks for valid object paths when unit testing, we don't
 * want that */
#undef DBUS_TYPE_OBJECT_PATH
#define DBUS_TYPE_OBJECT_PATH ((int) 's')

static struct ifp_ctx *
mock_ifp_ctx(TALLOC_CTX *mem_ctx)
{
    struct ifp_ctx *ifp_ctx;

    ifp_ctx = talloc_zero(mem_ctx, struct ifp_ctx);
    assert_non_null(ifp_ctx);

    ifp_ctx->rctx = mock_rctx(ifp_ctx, NULL, NULL, NULL);
    assert_non_null(ifp_ctx->rctx);

    ifp_ctx->rctx->allowed_uids = talloc_array(ifp_ctx->rctx, uint32_t, 1);
    assert_non_null(ifp_ctx->rctx->allowed_uids);
    ifp_ctx->rctx->allowed_uids[0] = geteuid();
    ifp_ctx->rctx->allowed_uids_count = 1;

    ifp_ctx->sysbus = talloc_zero(ifp_ctx, struct sysbus_ctx);
    assert_non_null(ifp_ctx->sysbus);

    ifp_ctx->sysbus->conn = talloc_zero(ifp_ctx, struct sbus_connection);
    assert_non_null(ifp_ctx->sysbus->conn);

    return ifp_ctx;
}

static struct sbus_request *
mock_sbus_request(TALLOC_CTX *mem_ctx, uid_t client)
{
    struct sbus_request *sr;

    sr = talloc_zero(mem_ctx, struct sbus_request);
    assert_non_null(sr);

    sr->conn = talloc_zero(sr, struct sbus_connection);
    assert_non_null(sr->conn);

    sr->message = dbus_message_new(DBUS_MESSAGE_TYPE_METHOD_CALL);
    assert_non_null(sr->message);
    dbus_message_set_serial(sr->message, 1);

    sr->client = client;

    return sr;
}

void ifp_test_req_create(void **state)
{
    struct ifp_req *ireq;
    struct sbus_request *sr;
    struct ifp_ctx *ifp_ctx;
    errno_t ret;

    assert_true(leak_check_setup());

    ifp_ctx = mock_ifp_ctx(global_talloc_context);
    assert_non_null(ifp_ctx);
    check_leaks_push(ifp_ctx);

    sr = mock_sbus_request(ifp_ctx, geteuid());
    assert_non_null(sr);
    check_leaks_push(sr);

    ret = ifp_req_create(sr, ifp_ctx, &ireq);
    assert_int_equal(ret, EOK);
    talloc_free(ireq);

    assert_true(check_leaks_pop(sr) == true);
    talloc_free(sr);

    assert_true(check_leaks_pop(ifp_ctx) == true);
    talloc_free(ifp_ctx);

    assert_true(leak_check_teardown());
}

void ifp_test_req_wrong_uid(void **state)
{
    struct ifp_req *ireq;
    struct sbus_request *sr;
    struct ifp_ctx *ifp_ctx;
    errno_t ret;

    assert_true(leak_check_setup());

    ifp_ctx = mock_ifp_ctx(global_talloc_context);
    assert_non_null(ifp_ctx);
    check_leaks_push(ifp_ctx);

    sr = mock_sbus_request(ifp_ctx, geteuid()+1);
    assert_non_null(sr);

    ret = ifp_req_create(sr, ifp_ctx, &ireq);
    assert_int_equal(ret, EACCES);
    talloc_free(sr);

    assert_true(check_leaks_pop(ifp_ctx) == true);
    talloc_free(ifp_ctx);

    assert_true(leak_check_teardown());
}

void test_el_to_dict(void **state)
{
    static struct sbus_request *sr;
    dbus_bool_t dbret;
    DBusMessageIter iter;
    DBusMessageIter iter_dict;
    struct ldb_message_element *el;
    errno_t ret;
    char *attr_name;
    char *attr_val;

    sr = mock_sbus_request(global_talloc_context, geteuid());
    assert_non_null(sr);

    el = talloc(sr, struct ldb_message_element);
    assert_non_null(el);
    el->name = "numbers";
    el->values = talloc_array(el, struct ldb_val, 2);
    assert_non_null(el->values);
    el->num_values = 2;
    el->values[0].data = (uint8_t *) discard_const("one");
    el->values[0].length = strlen("one") + 1;
    el->values[1].data = (uint8_t *) discard_const("two");
    el->values[1].length = strlen("two") + 1;

    dbus_message_iter_init_append(sr->message, &iter);
    dbret = dbus_message_iter_open_container(
                                      &iter, DBUS_TYPE_ARRAY,
                                      DBUS_DICT_ENTRY_BEGIN_CHAR_AS_STRING
                                      DBUS_TYPE_STRING_AS_STRING
                                      DBUS_TYPE_VARIANT_AS_STRING
                                      DBUS_DICT_ENTRY_END_CHAR_AS_STRING,
                                      &iter_dict);
    assert_true(dbret == TRUE);

    ret = ifp_add_ldb_el_to_dict(&iter_dict, el);
    assert_int_equal(ret, EOK);

    dbret = dbus_message_iter_close_container(&iter, &iter_dict);
    assert_true(dbret == TRUE);

    /* Test the reply contains what we expect */
    dbus_message_iter_init(sr->message, &iter);
    assert_int_equal(dbus_message_iter_get_arg_type(&iter),
                     DBUS_TYPE_ARRAY);
    dbus_message_iter_recurse(&iter, &iter);
    assert_int_equal(dbus_message_iter_get_arg_type(&iter),
                     DBUS_TYPE_DICT_ENTRY);

    dbus_message_iter_recurse(&iter, &iter_dict);
    dbus_message_iter_get_basic(&iter_dict, &attr_name);
    assert_string_equal(attr_name, "numbers");

    dbus_message_iter_next(&iter_dict);
    assert_int_equal(dbus_message_iter_get_arg_type(&iter_dict),
                     DBUS_TYPE_VARIANT);
    dbus_message_iter_recurse(&iter_dict, &iter_dict);
    assert_int_equal(dbus_message_iter_get_arg_type(&iter_dict),
                     DBUS_TYPE_ARRAY);

    dbus_message_iter_recurse(&iter_dict, &iter_dict);
    dbus_message_iter_get_basic(&iter_dict, &attr_val);
    assert_string_equal(attr_val, "one");
    assert_true(dbus_message_iter_next(&iter_dict));
    dbus_message_iter_get_basic(&iter_dict, &attr_val);
    assert_string_equal(attr_val, "two");
    assert_false(dbus_message_iter_next(&iter_dict));

    talloc_free(sr);
}

static void assert_string_list_equal(const char **s1,
                                     const char **s2)
{
    int i;

    for (i=0; s1[i]; i++) {
        assert_non_null(s2[i]);
        assert_string_equal(s1[i], s2[i]);
    }

    assert_null(s2[i]);
}

static void attr_parse_test(const char *expected[], const char *input)
{
    const char **res;
    TALLOC_CTX *test_ctx;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    res = ifp_parse_user_attr_list(test_ctx, input);

    if (expected) {
        /* Positive test */
        assert_non_null(res);
        assert_string_list_equal(res, expected);
    } else {
        /* Negative test */
        assert_null(res);
    }

    talloc_free(test_ctx);
}

static void attr_parse_test_ex(const char *expected[], const char *input,
                               const char **defaults)
{
    const char **res;
    TALLOC_CTX *test_ctx;

    test_ctx = talloc_new(NULL);
    assert_non_null(test_ctx);

    res = parse_attr_list_ex(test_ctx, input, defaults);

    if (expected) {
        /* Positive test */
        assert_non_null(res);
        assert_string_list_equal(res, expected);
    } else {
        /* Negative test */
        assert_null(res);
    }

    talloc_free(test_ctx);
}

void test_attr_acl(void **state)
{
    /* Test defaults */
    const char *exp_defaults[] = { SYSDB_NAME, SYSDB_UIDNUM,
                                   SYSDB_GIDNUM, SYSDB_GECOS,
                                   SYSDB_HOMEDIR, SYSDB_SHELL,
                                   "groups", "domain", "domainname", NULL };
    attr_parse_test(exp_defaults, NULL);

    /* Test adding some attributes to the defaults */
    const char *exp_add[] = { "telephoneNumber", "streetAddress",
                              SYSDB_NAME, SYSDB_UIDNUM,
                              SYSDB_GIDNUM, SYSDB_GECOS,
                              SYSDB_HOMEDIR, SYSDB_SHELL,
                              "groups", "domain", "domainname", NULL };
    attr_parse_test(exp_add, "+telephoneNumber, +streetAddress");

    /* Test removing some attributes to the defaults */
    const char *exp_rm[] = { SYSDB_NAME,
                             SYSDB_GIDNUM, SYSDB_GECOS,
                             SYSDB_HOMEDIR, "groups",
                             "domain", "domainname",
                             NULL };
    attr_parse_test(exp_rm, "-"SYSDB_SHELL ",-"SYSDB_UIDNUM);

    /* Test both add and remove */
    const char *exp_add_rm[] = { "telephoneNumber",
                                 SYSDB_NAME, SYSDB_UIDNUM,
                                 SYSDB_GIDNUM, SYSDB_GECOS,
                                 SYSDB_HOMEDIR, "groups",
                                 "domain", "domainname",
                                 NULL };
    attr_parse_test(exp_add_rm, "+telephoneNumber, -"SYSDB_SHELL);

    /* Test rm trumps add */
    const char *exp_add_rm_override[] = { SYSDB_NAME, SYSDB_UIDNUM,
                                          SYSDB_GIDNUM, SYSDB_GECOS,
                                          SYSDB_HOMEDIR, SYSDB_SHELL,
                                          "groups", "domain",
                                          "domainname", NULL };
    attr_parse_test(exp_add_rm_override,
                    "+telephoneNumber, -telephoneNumber, +telephoneNumber");

    /* Remove all */
    const char *rm_all[] = { NULL };
    attr_parse_test(rm_all,  "-"SYSDB_NAME ", -"SYSDB_UIDNUM
                             ", -"SYSDB_GIDNUM ", -"SYSDB_GECOS
                             ", -"SYSDB_HOMEDIR ", -"SYSDB_SHELL", -groups, "
                             "-domain, -domainname");

    /* Malformed list */
    attr_parse_test(NULL,  "missing_plus_or_minus");
}

void test_attr_acl_ex(void **state)
{
    /* Test defaults */
    const char *exp_defaults[] = { "abc", "123", "xyz", NULL };
    attr_parse_test_ex(exp_defaults, NULL, exp_defaults);

    /* Test adding some attributes to the defaults */
    const char *exp_add[] = { "telephoneNumber", "streetAddress",
                              "abc", "123", "xyz",
                              NULL };
    attr_parse_test_ex(exp_add, "+telephoneNumber, +streetAddress",
                       exp_defaults);

    /* Test removing some attributes to the defaults */
    const char *exp_rm[] = { "123", NULL };
    attr_parse_test_ex(exp_rm, "-abc, -xyz", exp_defaults);

    /* Test adding with empty defaults */
    const char *exp_add_empty[] = { "telephoneNumber", "streetAddress",
                                    NULL };
    attr_parse_test_ex(exp_add_empty, "+telephoneNumber, +streetAddress", NULL);

    /* Test removing with empty defaults */
    const char *rm_all[] = { NULL };
    attr_parse_test_ex(rm_all, "-telephoneNumber, -streetAddress", NULL);
}

void test_attr_allowed(void **state)
{
    const char *whitelist[] = { "name", "gecos", NULL };
    const char *emptylist[] = { NULL };

    assert_true(ifp_attr_allowed(whitelist, "name"));
    assert_true(ifp_attr_allowed(whitelist, "gecos"));

    assert_false(ifp_attr_allowed(whitelist, "password"));

    assert_false(ifp_attr_allowed(emptylist, "name"));
    assert_false(ifp_attr_allowed(NULL, "name"));
}

struct ifp_test_req_ctx {
    struct ifp_req *ireq;
    struct sbus_request *sr;
    struct ifp_ctx *ifp_ctx;
};

static int ifp_test_req_setup(void **state)
{
    struct ifp_test_req_ctx *test_ctx;
    errno_t ret;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct ifp_test_req_ctx);
    assert_non_null(test_ctx);
    test_ctx->ifp_ctx = mock_ifp_ctx(test_ctx);
    assert_non_null(test_ctx->ifp_ctx);

    test_ctx->sr = mock_sbus_request(test_ctx, geteuid());
    assert_non_null(test_ctx->sr);

    ret = ifp_req_create(test_ctx->sr, test_ctx->ifp_ctx, &test_ctx->ireq);
    assert_int_equal(ret, EOK);
    assert_non_null(test_ctx->ireq);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int ifp_test_req_teardown(void **state)
{
    struct ifp_test_req_ctx *test_ctx = talloc_get_type_abort(*state,
                                                struct ifp_test_req_ctx);

    assert_true(check_leaks_pop(test_ctx) == true);

    dbus_message_unref(test_ctx->sr->message);
    talloc_free(test_ctx);

    assert_true(leak_check_teardown());
    return 0;
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
        cmocka_unit_test(ifp_test_req_create),
        cmocka_unit_test(ifp_test_req_wrong_uid),
        cmocka_unit_test_setup_teardown(test_el_to_dict,
                                        ifp_test_req_setup,
                                        ifp_test_req_teardown),
        cmocka_unit_test(test_attr_acl),
        cmocka_unit_test(test_attr_acl_ex),
        cmocka_unit_test(test_attr_allowed),
    };

    /* Set debug level to invalid value so we can deside if -d 0 was used. */
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
     * they might not after a failed run. Remove the old db to be sure */
    tests_set_cwd();

    return cmocka_run_group_tests(tests, NULL, NULL);
}
