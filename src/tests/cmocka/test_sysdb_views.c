/*
    SSSD

    sysdb_views - Tests for view and override related sysdb calls

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "providers/ipa/ipa_id.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

#define TESTS_PATH "tests_sysdb_views"
#define TEST_CONF_FILE "tests_conf.ldb"

#define TEST_ANCHOR_PREFIX ":ANCHOR:"
#define TEST_VIEW_NAME "test view"
#define TEST_VIEW_CONTAINER "cn=" TEST_VIEW_NAME ",cn=views,cn=sysdb"
#define TEST_USER_NAME "test_user"
#define TEST_USER_UID 1234
#define TEST_USER_GID 5678
#define TEST_USER_GECOS "Gecos field"
#define TEST_USER_HOMEDIR "/home/home"
#define TEST_USER_SHELL "/bin/shell"
#define TEST_USER_SID "S-1-2-3-4"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int _setup_sysdb_tests(struct sysdb_test_ctx **ctx, bool enumerate)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    assert_true(ret == 0 || errno == EEXIST);

    test_ctx = talloc_zero(global_talloc_context, struct sysdb_test_ctx);
    assert_non_null(test_ctx);

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    assert_non_null(test_ctx->ev);

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    assert_non_null(conf_db);
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    assert_int_equal(ret, EOK);

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    assert_int_equal(ret, EOK);

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    assert_int_equal(ret, EOK);

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "local",
                           TESTS_PATH, &test_ctx->domain);
    assert_int_equal(ret, EOK);

    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)

static int test_sysdb_setup(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    ret = setup_sysdb_tests(&test_ctx);
    assert_int_equal(ret, EOK);

    *state = (void *) test_ctx;
    return 0;
}

static int test_sysdb_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    talloc_free(test_ctx);
    assert_true(leak_check_teardown());
    return 0;
}

static void test_sysdb_store_override(void **state)
{
    int ret;
    struct ldb_message *msg;
    struct ldb_message **msgs;
    struct sysdb_attrs *attrs;
    size_t count;
    const char override_dn_str[] = SYSDB_OVERRIDE_ANCHOR_UUID "=" \
                       TEST_ANCHOR_PREFIX TEST_USER_SID "," TEST_VIEW_CONTAINER;

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg = false;

    ret = sysdb_store_user(test_ctx->domain, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           0,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, TEST_USER_NAME,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    /* No override exists */
    ret = sysdb_store_override(test_ctx->domain, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, NULL, msg->dn);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_entry(test_ctx, test_ctx->domain->sysdb,msg->dn,
                             LDB_SCOPE_BASE, NULL, NULL, &count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(count, 1);
    assert_string_equal(ldb_dn_get_linearized(msg->dn),
                        ldb_msg_find_attr_as_string(msgs[0],
                                                    SYSDB_OVERRIDE_DN, NULL));

    ret = sysdb_invalidate_overrides(test_ctx->domain->sysdb);
    assert_int_equal(ret, EOK);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    /* Missing anchor attribute */
    ret = sysdb_store_override(test_ctx->domain, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EINVAL);

    /* With anchor */
    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_entry(test_ctx, test_ctx->domain->sysdb,msg->dn,
                             LDB_SCOPE_BASE, NULL, NULL, &count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(count, 1);
    assert_string_equal(override_dn_str, ldb_msg_find_attr_as_string(msgs[0],
                                                      SYSDB_OVERRIDE_DN, NULL));

}

void test_sysdb_add_overrides_to_object(void **state)
{
    int ret;
    struct ldb_message *orig;
    struct ldb_message *override;
    struct ldb_message_element *el;
    char *tmp_str;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    orig = ldb_msg_new(test_ctx);
    assert_non_null(orig);

    tmp_str = talloc_strdup(orig,  "ORIGNAME");
    ret = ldb_msg_add_string(orig, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(orig,  "ORIGGECOS");
    ret = ldb_msg_add_string(orig, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    override = ldb_msg_new(test_ctx);
    assert_non_null(override);

    tmp_str = talloc_strdup(override, "OVERRIDENAME");
    ret = ldb_msg_add_string(override, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEGECOS");
    ret = ldb_msg_add_string(override, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY1");
    ret = ldb_msg_add_string(override, SYSDB_SSH_PUBKEY, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY2");
    ret = ldb_msg_add_string(override, SYSDB_SSH_PUBKEY, tmp_str);
    assert_int_equal(ret, EOK);


    ret = sysdb_add_overrides_to_object(test_ctx->domain, orig, override, NULL);
    assert_int_equal(ret, EOK);

    assert_string_equal(ldb_msg_find_attr_as_string(orig, SYSDB_NAME, NULL),
                        "ORIGNAME");
    assert_string_equal(ldb_msg_find_attr_as_string(orig, SYSDB_GECOS, NULL),
                        "ORIGGECOS");
    assert_string_equal(ldb_msg_find_attr_as_string(orig,
                                                    OVERRIDE_PREFIX SYSDB_NAME,
                                                    NULL),
                        "OVERRIDENAME");
    assert_string_equal(ldb_msg_find_attr_as_string(orig,
                                                    OVERRIDE_PREFIX SYSDB_GECOS,
                                                    NULL),
                        "OVERRIDEGECOS");

    el = ldb_msg_find_element(orig, OVERRIDE_PREFIX SYSDB_SSH_PUBKEY);
    assert_non_null(el);
    assert_int_equal(el->num_values, 2);
    assert_int_equal(ldb_val_string_cmp(&el->values[0], "OVERRIDEKEY1"), 0);
    assert_int_equal(ldb_val_string_cmp(&el->values[1], "OVERRIDEKEY2"), 0);
}

void test_split_ipa_anchor(void **state)
{
    int ret;
    char *dom;
    char *uuid;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    ret = split_ipa_anchor(test_ctx, NULL, &dom, &uuid);
    assert_int_equal(ret, EINVAL);

    ret = split_ipa_anchor(test_ctx, "fwfkwjfkw", &dom, &uuid);
    assert_int_equal(ret, ENOMSG);

    ret = split_ipa_anchor(test_ctx, ":IPA:", &dom, &uuid);
    assert_int_equal(ret, EINVAL);

    ret = split_ipa_anchor(test_ctx, ":IPA:abc", &dom, &uuid);
    assert_int_equal(ret, EINVAL);

    ret = split_ipa_anchor(test_ctx, ":IPA:abc:", &dom, &uuid);
    assert_int_equal(ret, EINVAL);

    ret = split_ipa_anchor(test_ctx, ":IPA:abc:def", &dom, &uuid);
    assert_int_equal(ret, EOK);
    assert_string_equal(dom, "abc");
    assert_string_equal(uuid, "def");
}

void test_sysdb_delete_view_tree(void **state)
{
    int ret;
    struct ldb_message *msg;
    struct ldb_message **msgs = NULL;
    struct sysdb_attrs *attrs;
    size_t count;
    struct ldb_dn *views_dn;

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg = false;

    ret = sysdb_update_view_name(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->domain, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           0,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, TEST_USER_NAME,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EOK);

    views_dn = ldb_dn_new(test_ctx, test_ctx->domain->sysdb->ldb,
                          SYSDB_TMPL_VIEW_BASE);
    assert_non_null(views_dn);

    ret = sysdb_search_entry(test_ctx, test_ctx->domain->sysdb, views_dn,
                             LDB_SCOPE_SUBTREE, NULL, NULL, &count, &msgs);
    assert_int_equal(ret, EOK);
    assert_true(count > 1);
    assert_non_null(msgs);

    ret = sysdb_delete_view_tree(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_entry(test_ctx, test_ctx->domain->sysdb, views_dn,
                             LDB_SCOPE_SUBTREE, NULL, NULL, &count, &msgs);
    assert_int_equal(ret, EOK);
    assert_int_equal(count, 1);
    assert_true(ldb_dn_compare(views_dn, msgs[0]->dn) == 0);

}

void test_sysdb_invalidate_overrides(void **state)
{
    int ret;
    struct ldb_message *msg;
    struct sysdb_attrs *attrs;
    struct ldb_dn *views_dn;
    const char *user_attrs[] = { SYSDB_NAME,
                                 SYSDB_CACHE_EXPIRE,
                                 SYSDB_OVERRIDE_DN,
                                 NULL};

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg = false;

    ret = sysdb_update_view_name(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->domain, TEST_USER_NAME, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           10,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, TEST_USER_NAME,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EOK);

    views_dn = ldb_dn_new(test_ctx, test_ctx->domain->sysdb->ldb,
                          SYSDB_TMPL_VIEW_BASE);
    assert_non_null(views_dn);

    ret = sysdb_delete_view_tree(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, TEST_USER_NAME,
                                    user_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_true(ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0) > 1);
    assert_non_null(ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN, NULL));

    ret = sysdb_invalidate_overrides(test_ctx->domain->sysdb);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, TEST_USER_NAME,
                                    user_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_int_equal(ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0),
                     1);
    assert_null(ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN, NULL));
}

int main(int argc, const char *argv[])
{
    int rv;
    int no_cleanup = 0;
    poptContext pc;
    int opt;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_sysdb_store_override,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_add_overrides_to_object,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_split_ipa_anchor,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_delete_view_tree,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_invalidate_overrides,
                                        test_sysdb_setup, test_sysdb_teardown),
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

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, LOCAL_SYSDB_FILE);
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, LOCAL_SYSDB_FILE);
    }
    return rv;
}
