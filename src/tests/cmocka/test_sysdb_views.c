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

#include <stdlib.h>
#include <stdarg.h>
#include <stddef.h>
#include <setjmp.h>
#include <cmocka.h>
#include <popt.h>

#include "tests/cmocka/common_mock.h"
#include "providers/ipa/ipa_id.h"
#include "db/sysdb.h"
#include "db/sysdb_private.h" /* for sysdb->ldb member */

#define TESTS_PATH "tp_" BASE_FILE_STEM
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
#define TEST_GID_OVERRIDE_BASE 100

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

    val[0] = "FILES";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    assert_int_equal(ret, EOK);

    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "id_provider", val);
    assert_int_equal(ret, EOK);

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "enumerate", val);
    assert_int_equal(ret, EOK);

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "cache_credentials", val);
    assert_int_equal(ret, EOK);

    ret = test_domain_init(test_ctx, test_ctx->confdb, "FILES",
                           TESTS_PATH, &test_ctx->domain);
    assert_int_equal(ret, EOK);

    test_ctx->domain->has_views = true;
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)
#define setup_sysdb_enum_tests(ctx) _setup_sysdb_tests((ctx), true)

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
    char *name;
    const char override_dn_str[] = SYSDB_OVERRIDE_ANCHOR_UUID "=" \
                       TEST_ANCHOR_PREFIX TEST_USER_SID "," TEST_VIEW_CONTAINER;

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg_mode = MPG_DISABLED;
    name = sss_create_internal_fqname(test_ctx, TEST_USER_NAME,
                                      test_ctx->domain->name);
    assert_non_null(name);

    ret = sysdb_store_user(test_ctx->domain, name, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           0,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, name,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    /* No override exists */
    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
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
    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EINVAL);

    /* With anchor */
    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
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
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(orig,  "ORIGGECOS");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    override = ldb_msg_new(test_ctx);
    assert_non_null(override);

    tmp_str = talloc_strdup(override, "OVERRIDENAME");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(override, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEGECOS");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(override, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY1");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(override, SYSDB_SSH_PUBKEY, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(override, "OVERRIDEKEY2");
    assert_non_null(tmp_str);
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

void test_sysdb_add_overrides_to_object_local(void **state)
{
    int ret;
    struct ldb_message *orig;
    char *tmp_str;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    orig = ldb_msg_new(test_ctx);
    assert_non_null(orig);

    tmp_str = talloc_strdup(orig,  "ORIGNAME");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(orig,  "ORIGGECOS");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    test_ctx->domain->has_views = true;
    test_ctx->domain->view_name = "LOCAL";

    ret = sysdb_add_overrides_to_object(test_ctx->domain, orig, NULL, NULL);
    assert_int_equal(ret, EOK);
}

void test_sysdb_add_overrides_to_object_missing_overridedn(void **state)
{
    int ret;
    struct ldb_message *orig;
    char *tmp_str;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    orig = ldb_msg_new(test_ctx);
    assert_non_null(orig);

    orig->dn = ldb_dn_new(orig, test_ctx->domain->sysdb->ldb,
                          "cn=somedn,dc=example,dc=com");
    assert_non_null(orig->dn);

    tmp_str = talloc_strdup(orig,  "ORIGNAME");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_NAME, tmp_str);
    assert_int_equal(ret, EOK);

    tmp_str = talloc_strdup(orig,  "ORIGGECOS");
    assert_non_null(tmp_str);
    ret = ldb_msg_add_string(orig, SYSDB_GECOS, tmp_str);
    assert_int_equal(ret, EOK);

    test_ctx->domain->has_views = true;
    test_ctx->domain->view_name = "NON-LOCAL";

    ret = sysdb_add_overrides_to_object(test_ctx->domain, orig, NULL, NULL);
    assert_int_equal(ret, ENOENT);
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
    char *name;

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg_mode = MPG_DISABLED;

    ret = sysdb_update_view_name(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    name = sss_create_internal_fqname(test_ctx, TEST_USER_NAME,
                                      test_ctx->domain->name);
    assert_non_null(name);

    ret = sysdb_store_user(test_ctx->domain, name, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           0,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, name,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
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
    char *name;
    const char *user_attrs[] = { SYSDB_NAME,
                                 SYSDB_CACHE_EXPIRE,
                                 SYSDB_OVERRIDE_DN,
                                 NULL};

    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                         struct sysdb_test_ctx);

    test_ctx->domain->mpg_mode = MPG_DISABLED;
    name = sss_create_internal_fqname(test_ctx, TEST_USER_NAME,
                                      test_ctx->domain->name);
    assert_non_null(name);


    ret = sysdb_update_view_name(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_user(test_ctx->domain, name, NULL,
                           TEST_USER_UID, TEST_USER_GID, TEST_USER_GECOS,
                           TEST_USER_HOMEDIR, TEST_USER_SHELL, NULL, NULL, NULL,
                           10,0);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, name,
                                    NULL, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);

    attrs = sysdb_new_attrs(test_ctx);
    assert_non_null(attrs);

    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID,
                                 TEST_ANCHOR_PREFIX TEST_USER_SID);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, msg->dn);
    assert_int_equal(ret, EOK);

    views_dn = ldb_dn_new(test_ctx, test_ctx->domain->sysdb->ldb,
                          SYSDB_TMPL_VIEW_BASE);
    assert_non_null(views_dn);

    ret = sysdb_delete_view_tree(test_ctx->domain->sysdb, TEST_VIEW_NAME);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, name,
                                    user_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_true(ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0) > 1);
    assert_non_null(ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN, NULL));

    ret = sysdb_invalidate_overrides(test_ctx->domain->sysdb);
    assert_int_equal(ret, EOK);

    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain, name,
                                    user_attrs, &msg);
    assert_int_equal(ret, EOK);
    assert_non_null(msg);
    assert_int_equal(ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0),
                     1);
    assert_null(ldb_msg_find_attr_as_string(msg, SYSDB_OVERRIDE_DN, NULL));

    ret = sysdb_delete_user(test_ctx->domain, name, 0);
    assert_int_equal(ret, EOK);
}

static const char *users[] = { "alice", "bob", "barney", NULL };

static void enum_test_user_override(struct sysdb_test_ctx *test_ctx,
                                    const char *name)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    const char *anchor;
    const char *override_gecos;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    attrs = sysdb_new_attrs(tmp_ctx);
    assert_non_null(attrs);

    dn = sysdb_user_dn(tmp_ctx, test_ctx->domain, name);
    assert_non_null(dn);

    anchor = talloc_asprintf(tmp_ctx, "%s%s", TEST_ANCHOR_PREFIX, name);
    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    assert_int_equal(ret, EOK);

    override_gecos = talloc_asprintf(attrs, "%s_GECOS_OVERRIDE", name);
    ret = sysdb_attrs_add_string(attrs, SYSDB_GECOS, override_gecos);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
                               SYSDB_MEMBER_USER, attrs, dn);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
}

static void enum_test_add_users(struct sysdb_test_ctx *test_ctx,
                                const char *usernames[])
{
    int i;
    int ret;
    struct sysdb_attrs *attrs;
    char *fqname = NULL;

    for (i = 0; usernames[i] != NULL; i++) {
        attrs = talloc(test_ctx, struct sysdb_attrs);
        assert_non_null(attrs);
        fqname = sss_create_internal_fqname(test_ctx, usernames[i],
                                            test_ctx->domain->name);
        assert_non_null(fqname);

        ret = sysdb_store_user(test_ctx->domain, fqname,
                               NULL, 1234 + i, 1234 + i, fqname, "/", "/bin/sh",
                               NULL, NULL, NULL, 1, 1234 + i);
        assert_int_equal(ret, EOK);

        enum_test_user_override(test_ctx, fqname);

        talloc_free(attrs);
        talloc_free(fqname);
    }
}

static void enum_test_del_users(struct sysdb_test_ctx *test_ctx,
                                const char *usernames[])
{
    int i;
    int ret;
    char *fqname = NULL;

    for (i = 0; usernames[i] != NULL; i++) {
        fqname = sss_create_internal_fqname(test_ctx, usernames[i],
                                            test_ctx->domain->name);
        assert_non_null(fqname);

        ret = sysdb_delete_user(test_ctx->domain, fqname, 0);
        talloc_free(fqname);
        if (ret != EOK && ret != ENOENT) {
            fail();
        }
    }
}

static int test_enum_users_setup(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    ret = setup_sysdb_enum_tests(&test_ctx);
    assert_int_equal(ret, EOK);

    enum_test_add_users(test_ctx, users);

    *state = (void *) test_ctx;
    return 0;
}

static int cmp_func(const void *a, const void *b)
{
    const char *str1;
    const char *str2;
    struct ldb_message *msg1 = *(struct ldb_message **)discard_const(a);
    struct ldb_message *msg2 = *(struct ldb_message **)discard_const(b);

    str1 = ldb_msg_find_attr_as_string(msg1, SYSDB_NAME, NULL);
    str2 = ldb_msg_find_attr_as_string(msg2, SYSDB_NAME, NULL);

    return strcmp(str1, str2);
}

/* Make the order of ldb results deterministic */
static void order_ldb_res_msgs(struct ldb_result *res)
{
    if (res == NULL || res->count < 2) {
        /* Nothing to do */
        return;
    }

    qsort(res->msgs, res->count, sizeof(struct ldb_message *), cmp_func);
    return;
}

static void assert_user_attrs(struct ldb_message *msg,
                              struct sss_domain_info *dom,
                              const char *shortname,
                              bool has_views)
{
    const char *str;
    char *fqname;

    fqname = sss_create_internal_fqname(msg, shortname, dom->name);
    assert_non_null(fqname);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    assert_string_equal(str, fqname);
    str = ldb_msg_find_attr_as_string(msg, SYSDB_GECOS, NULL);
    assert_string_equal(str, fqname);

    str = ldb_msg_find_attr_as_string(msg, OVERRIDE_PREFIX SYSDB_GECOS, NULL);
    if (has_views) {
        char *override;

        assert_non_null(str);
        override = talloc_asprintf(msg, "%s_GECOS_OVERRIDE", fqname);
        assert_non_null(override);

        assert_string_equal(str, override);
        talloc_free(override);
    } else {
        assert_null(str);
    }

    talloc_free(fqname);
}

static int test_enum_users_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);

    enum_test_del_users(test_ctx, users);
    return test_sysdb_teardown(state);
}

static void check_enumpwent(int ret, struct sss_domain_info *dom,
                            struct ldb_result *res, bool views)
{
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, N_ELEMENTS(users)-1);

    order_ldb_res_msgs(res);
    assert_user_attrs(res->msgs[0], dom, "alice", views);
    assert_user_attrs(res->msgs[1], dom, "barney", views);
    assert_user_attrs(res->msgs[2], dom, "bob", views);
}

static void test_sysdb_enumpwent(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;

    ret = sysdb_enumpwent(test_ctx, test_ctx->domain, &res);
    check_enumpwent(ret, test_ctx->domain, res, false);
}

static void test_sysdb_enumpwent_views(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;

    ret = sysdb_enumpwent_with_views(test_ctx, test_ctx->domain, &res);
    check_enumpwent(ret, test_ctx->domain, res, true);
}

static void test_sysdb_enumpwent_filter(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;
    char *addtl_filter;

    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_UIDNUM, "1234",
                                 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "alice", false);

    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "a*",
                                 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "alice", false);

    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "b*",
                                 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 2);
    order_ldb_res_msgs(res);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "barney", false);
    assert_user_attrs(res->msgs[1], test_ctx->domain, "bob", false);

    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "c*",
                                 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "*",
                                 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, N_ELEMENTS(users)-1);

    /* Test searching based on time as well */
    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1233);
    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "a*",
                                 addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1234);
    ret = sysdb_enumpwent_filter(test_ctx, test_ctx->domain, SYSDB_NAME, "a*",
                                 addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "alice", false);
}

static void test_sysdb_enumpwent_filter_views(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;
    char *addtl_filter;

    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_UIDNUM, "1234", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "alice", true);

    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_NAME, "a*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "alice", true);

    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_NAME, "b*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 2);
    order_ldb_res_msgs(res);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "barney", true);
    assert_user_attrs(res->msgs[1], test_ctx->domain, "bob", true);

    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1235);
    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_NAME, "b*", addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_user_attrs(res->msgs[0], test_ctx->domain, "bob", true);

    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_NAME, "c*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sysdb_enumpwent_filter_with_views(test_ctx, test_ctx->domain,
                                            SYSDB_NAME, "*", NULL, &res);
    check_enumpwent(ret, test_ctx->domain, res, true);
}

static const char *groups[] = { "one", "two", "three", NULL };

static void enum_test_group_override(struct sysdb_test_ctx *test_ctx,
                                     const char *name,
                                     unsigned override_gid)
{
    int ret;
    struct sysdb_attrs *attrs;
    struct ldb_dn *dn;
    TALLOC_CTX *tmp_ctx;
    const char *anchor;

    tmp_ctx = talloc_new(test_ctx);
    assert_non_null(tmp_ctx);

    attrs = sysdb_new_attrs(tmp_ctx);
    assert_non_null(attrs);

    dn = sysdb_group_dn(tmp_ctx, test_ctx->domain, name);
    assert_non_null(dn);

    anchor = talloc_asprintf(tmp_ctx, "%s%s", TEST_ANCHOR_PREFIX, name);
    ret = sysdb_attrs_add_string(attrs, SYSDB_OVERRIDE_ANCHOR_UUID, anchor);
    assert_int_equal(ret, EOK);

    ret = sysdb_attrs_add_uint32(attrs, SYSDB_GIDNUM, override_gid);
    assert_int_equal(ret, EOK);

    ret = sysdb_store_override(test_ctx->domain, NULL, NULL, TEST_VIEW_NAME,
                               SYSDB_MEMBER_GROUP, attrs, dn);
    assert_int_equal(ret, EOK);

    talloc_free(tmp_ctx);
}

static void enum_test_add_groups(struct sysdb_test_ctx *test_ctx,
                                 const char *groupnames[])
{
    int i;
    int ret;
    struct sysdb_attrs *attrs;
    char *gr_name;

    for (i = 0; groupnames[i] != NULL; i++) {
        attrs = talloc(test_ctx, struct sysdb_attrs);
        assert_non_null(attrs);

        gr_name = sss_create_internal_fqname(test_ctx, groupnames[i],
                                             test_ctx->domain->name);
        ret = sysdb_store_group(test_ctx->domain, gr_name,
                                0, NULL, 1, 1234 + i);
        assert_int_equal(ret, EOK);

        enum_test_group_override(test_ctx, gr_name,
                                 TEST_GID_OVERRIDE_BASE + i);
        talloc_free(attrs);
    }
}

static void enum_test_del_groups(struct sss_domain_info *dom,
                                 const char *groupnames[])
{
    int i;
    int ret;

    for (i = 0; groupnames[i] != NULL; i++) {
        ret = sysdb_delete_group(dom, groupnames[i], 0);
        if (ret != EOK && ret != ENOENT) {
            fail();
        }
    }
}

static int test_enum_groups_setup(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;

    assert_true(leak_check_setup());

    ret = setup_sysdb_enum_tests(&test_ctx);
    assert_int_equal(ret, EOK);

    enum_test_add_groups(test_ctx, groups);

    *state = (void *) test_ctx;
    return 0;
}

static int test_enum_groups_teardown(void **state)
{
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);

    enum_test_del_groups(test_ctx->domain, groups);
    return test_sysdb_teardown(state);
}

static void assert_group_attrs(struct ldb_message *msg,
                               struct sss_domain_info *dom,
                               const char *shortname,
                               unsigned expected_override_gid)
{
    const char *str;
    unsigned gid;
    char *fqname;

    fqname = sss_create_internal_fqname(msg, shortname, dom->name);
    assert_non_null(fqname);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    assert_string_equal(str, fqname);

    if (expected_override_gid) {
        gid = ldb_msg_find_attr_as_uint64(msg,
                                          OVERRIDE_PREFIX SYSDB_GIDNUM, 0);
        assert_int_equal(gid, expected_override_gid);
    }
}

static void check_enumgrent(int ret, struct sss_domain_info *dom,
                            struct ldb_result *res, bool views)
{
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, N_ELEMENTS(groups)-1);
    order_ldb_res_msgs(res);
    assert_group_attrs(res->msgs[0], dom, "one",
                       views ? TEST_GID_OVERRIDE_BASE : 0);
    assert_group_attrs(res->msgs[1], dom, "three",
                       views ? TEST_GID_OVERRIDE_BASE + 2 : 0);
    assert_group_attrs(res->msgs[2], dom, "two",
                       views ? TEST_GID_OVERRIDE_BASE + 1 : 0);
}

static void test_sysdb_enumgrent(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;

    ret = sysdb_enumgrent(test_ctx, test_ctx->domain, &res);
    check_enumgrent(ret, test_ctx->domain, res, false);
}

static void test_sysdb_enumgrent_views(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;

    ret = sysdb_enumgrent_with_views(test_ctx, test_ctx->domain, &res);
    check_enumgrent(ret, test_ctx->domain, res, true);
}

static void test_sysdb_enumgrent_filter(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;
    char *addtl_filter;

    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "o*", 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_group_attrs(res->msgs[0], test_ctx->domain, "one", 0);

    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "t*", 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 2);
    order_ldb_res_msgs(res);
    assert_group_attrs(res->msgs[0], test_ctx->domain, "three", 0);
    assert_group_attrs(res->msgs[1], test_ctx->domain, "two", 0);

    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "x*", 0, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "*", 0, &res);
    check_enumgrent(ret, test_ctx->domain, res, false);

    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1233);
    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "o*", addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1234);
    ret = sysdb_enumgrent_filter(test_ctx, test_ctx->domain, "o*", addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_group_attrs(res->msgs[0], test_ctx->domain, "one", 0);

}

static void test_sysdb_enumgrent_filter_views(void **state)
{
    int ret;
    struct sysdb_test_ctx *test_ctx = talloc_get_type_abort(*state,
                                                        struct sysdb_test_ctx);
    struct ldb_result *res;
    char *addtl_filter;

    ret = sysdb_enumgrent_filter_with_views(test_ctx, test_ctx->domain,
                                            "o*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_group_attrs(res->msgs[0], test_ctx->domain,
                       "one", TEST_GID_OVERRIDE_BASE);

    ret = sysdb_enumgrent_filter_with_views(test_ctx, test_ctx->domain,
                                            "t*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 2);
    order_ldb_res_msgs(res);
    assert_group_attrs(res->msgs[0], test_ctx->domain,
                       "three", TEST_GID_OVERRIDE_BASE + 2);
    assert_group_attrs(res->msgs[1], test_ctx->domain, "two",
                       TEST_GID_OVERRIDE_BASE + 1);

    addtl_filter = talloc_asprintf(test_ctx, "(%s<=%d)",
                                   SYSDB_LAST_UPDATE, 1235);
    ret = sysdb_enumgrent_filter_with_views(test_ctx, test_ctx->domain,
                                            "t*", addtl_filter, &res);
    talloc_free(addtl_filter);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 1);
    assert_group_attrs(res->msgs[0], test_ctx->domain, "two",
                       TEST_GID_OVERRIDE_BASE + 1);

    ret = sysdb_enumgrent_filter_with_views(test_ctx, test_ctx->domain,
                                            "x*", NULL, &res);
    assert_int_equal(ret, EOK);
    assert_int_equal(res->count, 0);

    ret = sysdb_enumgrent_filter_with_views(test_ctx, test_ctx->domain,
                                            "*", NULL, &res);
    check_enumgrent(ret, test_ctx->domain, res, true);
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
        cmocka_unit_test_setup_teardown(test_sysdb_add_overrides_to_object_local,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_add_overrides_to_object_missing_overridedn,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_split_ipa_anchor,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_delete_view_tree,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_invalidate_overrides,
                                        test_sysdb_setup, test_sysdb_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumpwent,
                                        test_enum_users_setup,
                                        test_enum_users_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumpwent_views,
                                        test_enum_users_setup,
                                        test_enum_users_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumpwent_filter,
                                        test_enum_users_setup,
                                        test_enum_users_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumpwent_filter_views,
                                        test_enum_users_setup,
                                        test_enum_users_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumgrent,
                                        test_enum_groups_setup,
                                        test_enum_groups_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumgrent_views,
                                        test_enum_groups_setup,
                                        test_enum_groups_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumgrent_filter,
                                        test_enum_groups_setup,
                                        test_enum_groups_teardown),
        cmocka_unit_test_setup_teardown(test_sysdb_enumgrent_filter_views,
                                        test_enum_groups_setup,
                                        test_enum_groups_teardown),
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

    tests_set_cwd();
    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");
    test_dom_suite_setup(TESTS_PATH);
    rv = cmocka_run_group_tests(tests, NULL, NULL);

    if (rv == 0 && no_cleanup == 0) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");
    }
    return rv;
}
