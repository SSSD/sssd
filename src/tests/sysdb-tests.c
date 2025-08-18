/*
   SSSD

   System Database

   Copyright (C) Stephen Gallagher <sgallagh@redhat.com>	2009

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
#include <check.h>
#include <talloc.h>
#include <tevent.h>
#include <ctype.h>
#include <popt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include "util/util.h"
#include "util/crypto/sss_crypto.h"
#include "providers/ipa/ipa_subdomains.h"
#include "db/sysdb_private.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "db/sysdb_iphosts.h"
#include "db/sysdb_ipnetworks.h"
#include "tests/common_check.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_FILE "tests_conf.ldb"

#define TEST_ATTR_NAME "test_attr_name"
#define TEST_ATTR_VALUE "test_attr_value"
#define TEST_ATTR_UPDATE_VALUE "test_attr_update_value"
#define TEST_ATTR_ADD_NAME "test_attr_add_name"
#define TEST_ATTR_ADD_VALUE "test_attr_add_value"
#define CUSTOM_TEST_CONTAINER "custom_test_container"
#define CUSTOM_TEST_OBJECT "custom_test_object"

#define ASQ_TEST_USER "testuser27010"
#define ASQ_TEST_USER_UID 27010

#define MBO_USER_BASE 27500
#define MBO_GROUP_BASE 28500
#define NUM_GHOSTS 10

#define TEST_AUTOFS_MAP_BASE 29500

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;

    size_t null_pointer_size;
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
    if (ret == -1 && errno != EEXIST) {
        ck_abort_msg("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    test_ctx = talloc_zero(NULL, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        ck_abort_msg("Could not allocate memory for test context");
        return ENOMEM;
    }

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        ck_abort_msg("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        ck_abort_msg("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "FILES";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "proxy";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "id_provider", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "enumerate", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize FILES domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/FILES", "cache_credentials", val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize FILES domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "FILES",
                           TESTS_PATH, &test_ctx->domain);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }
    test_ctx->sysdb = test_ctx->domain->sysdb;

    test_ctx->null_pointer_size = talloc_total_size(NULL);

    *ctx = test_ctx;
    return EOK;
}

static void null_ctx_get_size(struct sysdb_test_ctx *ctx)
{
    ctx->null_pointer_size = talloc_total_size(NULL);
}

static void fail_if_null_ctx_leaks(struct sysdb_test_ctx *ctx)
{
    size_t new_null_pointer_size;

    new_null_pointer_size = talloc_total_size(NULL);
    if(new_null_pointer_size != ctx->null_pointer_size) {
        ck_abort_msg("NULL pointer leaked memory, was %zu, is %zu\n",
             ctx->null_pointer_size, new_null_pointer_size);
    }
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)

struct test_data {
    struct tevent_context *ev;
    struct sysdb_test_ctx *ctx;

    const char *username;           /* fqname */
    const char *groupname;          /* fqname */
    const char *netgrname;
    const char *autofsmapname;
    uid_t uid;
    gid_t gid;
    const char *shell;
    const char *orig_dn;
    const char *sid_str;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char **attrlist;
    char **ghostlist;
    struct ldb_message *msg;

    size_t msgs_count;
    struct ldb_message **msgs;
};

static struct test_data *test_data_new(struct sysdb_test_ctx *test_ctx)
{
    struct test_data *data;

    data = talloc_zero(test_ctx, struct test_data);
    if (data == NULL) {
        return NULL;
    }

    data->attrs = sysdb_new_attrs(data);
    if (data->attrs == NULL) {
        talloc_free(data);
        return NULL;
    }

    data->ctx = test_ctx;
    data->ev = test_ctx->ev;

    return data;
}

static char *test_asprintf_fqname(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom,
                                  const char *fmt,
                                  ...)
{
    char *shortname;
    char *fqname;
    va_list ap;

    va_start(ap, fmt);
    shortname = talloc_vasprintf(mem_ctx, fmt, ap);
    va_end(ap);
    if (shortname == NULL) {
        return NULL;
    }

    fqname = sss_create_internal_fqname(mem_ctx, shortname, dom->name);
    talloc_free(shortname);
    if (fqname == NULL) {
        return NULL;
    }

    return fqname;
}

static struct test_data *test_data_new_user(struct sysdb_test_ctx *test_ctx,
                                            uid_t uid)
{
    struct test_data *data;

    data = test_data_new(test_ctx);
    if (data == NULL) {
        return NULL;
    }

    data->uid = uid;
    data->gid = uid;
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testuser%d", uid);
    if (data->username == NULL) {
        talloc_free(data);
        return NULL;
    }

    return data;
}

static struct test_data *test_data_new_group(struct sysdb_test_ctx *test_ctx,
                                             gid_t gid)
{
    struct test_data *data;

    data = test_data_new(test_ctx);
    if (data == NULL) {
        return NULL;
    }

    data->gid = gid;
    data->groupname = test_asprintf_fqname(data, test_ctx->domain,
                                           "testgroup%d", gid);
    if (data->groupname == NULL) {
        talloc_free(data);
        return NULL;
    }

    return data;
}

static int test_add_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    if (homedir == NULL) {
        return ENOMEM;
    }

    gecos = talloc_asprintf(data, "Test User %d", data->uid);
    if (gecos == NULL) {
        return ENOMEM;
    }

    ret = sysdb_add_user(data->ctx->domain, data->username,
                         data->uid, 0, gecos, homedir, "/bin/bash",
                         data->orig_dn, data->attrs, 0, 0);
    return ret;
}

static int test_store_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    sss_ck_fail_if_msg(homedir == NULL, "OOM");
    gecos = talloc_asprintf(data, "Test User %d", data->uid);
    sss_ck_fail_if_msg(gecos == NULL, "OOM");

    ret = sysdb_store_user(data->ctx->domain,
                           data->username, "x",
                           data->uid, 0, gecos, homedir,
                           data->shell ? data->shell : "/bin/bash",
                           NULL, NULL, NULL, -1, 0);
    return ret;
}

static int test_remove_user(struct test_data *data)
{
    struct ldb_dn *user_dn;
    int ret;
    struct ldb_result *res;

    user_dn = sysdb_user_dn(data, data->ctx->domain, data->username);
    if (!user_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, user_dn, false);
    if (ret != EOK) return ret;

    ret = sysdb_getpwnam(data, data->ctx->domain, data->username, &res);
    if (ret != EOK) return ret;

    if (res->count != 0) return E2BIG;

    return EOK;
}

static int test_remove_user_by_uid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_add_group(struct test_data *data)
{
    int ret;

    ret = sysdb_add_group(data->ctx->domain, data->groupname, data->gid,
                          data->attrs, 0, 0);
    return ret;
}

static int test_add_incomplete_group(struct test_data *data)
{
    int ret;

    ret = sysdb_add_incomplete_group(data->ctx->domain, data->groupname,
                                     data->gid, data->orig_dn,
                                     data->sid_str, NULL, true, 0);
    return ret;
}

static int test_store_group(struct test_data *data)
{
    int ret;

    ret = sysdb_store_group(data->ctx->domain,
                            data->groupname, data->gid, data->attrs, -1, 0);
    return ret;
}

static int test_remove_group(struct test_data *data)
{
    struct ldb_dn *group_dn;
    int ret;
    struct ldb_result *res;

    group_dn = sysdb_group_dn(data, data->ctx->domain, data->groupname);
    if (!group_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, group_dn, true);
    if (ret != EOK) return ret;

    ret = sysdb_getgrnam(data, data->ctx->domain, data->groupname, &res);
    if (ret != EOK) return ret;

    if (res->count != 0) return E2BIG;

    return EOK;
}

static int test_remove_group_by_gid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data->ctx->domain, NULL, data->gid);
    return ret;
}

static int test_set_user_attr(struct test_data *data)
{
    int ret;

    ret = sysdb_set_user_attr(data->ctx->domain, data->username,
                              data->attrs, SYSDB_MOD_REP);
    return ret;
}

static int test_add_group_member(struct test_data *data)
{
    int ret;

    ret = sysdb_add_group_member(data->ctx->domain,
                                 data->groupname,
                                 data->username,
                                 SYSDB_MEMBER_USER, false);
    return ret;
}

static int test_remove_group_member(struct test_data *data)
{
    int ret;
    struct ldb_result *res_pre;
    struct ldb_result *res_post;

    ret = sysdb_initgroups(data, data->ctx->domain, data->username, &res_pre);
    if (ret) return ret;

    ret = sysdb_remove_group_member(data->ctx->domain,
                                    data->groupname,
                                    data->username,
                                    SYSDB_MEMBER_USER, false);

    ret = sysdb_initgroups(data, data->ctx->domain, data->username, &res_post);
    if (ret) return ret;

    /* assert the member was removed */
    if (res_post->count + 1 != res_pre->count) {
        return E2BIG;
    }

    return ret;
}

static int test_store_custom(struct test_data *data)
{
    char *object_name;
    int ret;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, data->uid);
    if (!object_name) {
        return ENOMEM;
    }

    ret = sysdb_store_custom(data->ctx->domain, object_name,
                             CUSTOM_TEST_CONTAINER, data->attrs);
    return ret;
}

static int test_delete_custom(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_custom(data->ctx->domain, CUSTOM_TEST_OBJECT,
                              CUSTOM_TEST_CONTAINER);
    return ret;
}

static int test_search_all_users(struct test_data *data)
{
    struct ldb_dn *base_dn;
    int ret;

    base_dn = ldb_dn_new_fmt(data, data->ctx->sysdb->ldb, SYSDB_TMPL_USER_BASE,
                             "FILES");
    if (base_dn == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_entry(data, data->ctx->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, SYSDB_UC,
                             data->attrlist, &data->msgs_count, &data->msgs);
    return ret;
}

static int test_delete_recursive(struct test_data *data)
{
    struct ldb_dn *dn;
    int ret;

    dn = ldb_dn_new_fmt(data, data->ctx->sysdb->ldb, SYSDB_DOM_BASE,
                        "FILES");
    if (!dn) {
        return ENOMEM;
    }

    ret = sysdb_delete_recursive(data->ctx->sysdb, dn, false);
    ck_assert_msg(ret == EOK, "sysdb_delete_recursive returned [%d]", ret);
    return ret;
}

static int test_memberof_store_group(struct test_data *data)
{
    int ret;
    char *member;
    int i;

    for (i = 0; data->attrlist && data->attrlist[i]; i++) {
        member = sysdb_group_strdn(data, data->ctx->domain->name,
                                   data->attrlist[i]);
        if (!member) {
            return ENOMEM;
        }
        ret = sysdb_attrs_steal_string(data->attrs, SYSDB_MEMBER, member);
        if (ret != EOK) {
            return ret;
        }
    }

    return test_store_group(data);
}

static int test_memberof_store_group_with_ghosts(struct test_data *data)
{
    int ret;
    struct sysdb_attrs *attrs = NULL;
    char *member;
    int i;

    attrs = sysdb_new_attrs(data);
    if (!attrs) {
        return ENOMEM;
    }

    for (i = 0; data->attrlist && data->attrlist[i]; i++) {
        member = sysdb_group_strdn(data, data->ctx->domain->name,
                                   data->attrlist[i]);
        if (!member) {
            return ENOMEM;
        }
        ret = sysdb_attrs_steal_string(attrs, SYSDB_MEMBER, member);
        if (ret != EOK) {
            return ret;
        }
    }

    for (i = 0; data->ghostlist && data->ghostlist[i]; i++) {
        ret = sysdb_attrs_steal_string(attrs, SYSDB_GHOST,
                                       data->ghostlist[i]);
        if (ret != EOK) {
            return ret;
        }
    }

    ret = sysdb_store_group(data->ctx->domain,
                            data->groupname, data->gid, attrs, -1, 0);
    return ret;
}

static int test_add_basic_netgroup(struct test_data *data)
{
    const char *description;
    int ret;

    description = talloc_asprintf(data, "Test Netgroup %d", data->uid);
    if (description == NULL) return ENOMEM;

    ret = sysdb_add_basic_netgroup(data->ctx->domain, data->netgrname,
                                   description);
    return ret;
}

static int test_remove_netgroup_entry(struct test_data *data)
{
    struct ldb_dn *netgroup_dn;
    int ret;

    netgroup_dn = sysdb_netgroup_dn(data, data->ctx->domain, data->netgrname);
    if (!netgroup_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, netgroup_dn, true);
    return ret;
}

static int test_remove_netgroup_by_name(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_netgroup(data->ctx->domain, data->netgrname);
    return ret;
}

static int test_set_netgroup_attr(struct test_data *data)
{
    int ret;
    const char *description;
    struct sysdb_attrs *attrs = NULL;

    description = talloc_asprintf(data, "Sysdb Netgroup %d", data->uid);
    if (description == NULL) return ENOMEM;

    attrs = sysdb_new_attrs(data);
    if (!attrs) {
        return ENOMEM;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_DESCRIPTION, description);
    if (ret) {
        return ret;
    }

    ret = sysdb_set_netgroup_attr(data->ctx->domain, data->netgrname,
                                  attrs, SYSDB_MOD_REP);
    return ret;
}

static struct ldb_result *test_getpwnam(struct test_data *data)
{
    int ret;
    struct ldb_result *res;

    ret = sysdb_getpwnam(data,
                         data->ctx->domain,
                         data->username, &res);
    if (ret != EOK) {
        return NULL;
    }

    return res;
}

static struct ldb_result *test_getgrnam(struct test_data *data)
{
    int ret;
    struct ldb_result *res;

    ret = sysdb_getgrnam(data,
                         data->ctx->domain,
                         data->groupname, &res);
    if (ret != EOK) {
        return NULL;
    }

    return res;
}

START_TEST (test_sysdb_user_new_id)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *fqname;
    struct sysdb_attrs *attrs = NULL;
    struct ldb_message *msg;
    const char *get_attrs[] = { SYSDB_DESCRIPTION, NULL };
    const char *desc;
    const char *desc_in = "testuser_new_id_desc";
    const char *username = "testuser_newid";

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    fqname = sss_create_internal_fqname(test_ctx,
                                        username,
                                        test_ctx->domain->name);
    sss_ck_fail_if_msg(fqname == NULL, "Failed to allocate memory");

    attrs = sysdb_new_attrs(test_ctx);
    sss_ck_fail_if_msg(attrs == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_string(attrs, SYSDB_DESCRIPTION, desc_in);
    sss_ck_fail_if_msg(ret != EOK, "Failed to add attribute: " SYSDB_DESCRIPTION);

    ret = sysdb_add_user(test_ctx->domain, fqname,
                         1234, 1234, fqname, "/", "/bin/bash",
                         NULL, attrs, 0, 0);
    sss_ck_fail_if_msg(ret != EOK, "Could not store user %s", fqname);

    ret = sysdb_search_user_by_name(test_ctx,
                                    test_ctx->domain,
                                    fqname, get_attrs, &msg);
    sss_ck_fail_if_msg(ret != EOK, "Could not retrieve user %s", fqname);

    desc = ldb_msg_find_attr_as_string(msg, SYSDB_DESCRIPTION, NULL);
    ck_assert_msg(desc != NULL, "Failed to find attribute: " SYSDB_DESCRIPTION);
    ck_assert_str_eq(desc, desc_in);

    ret = sysdb_delete_user(test_ctx->domain, fqname, 0);
    ck_assert_msg(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_store_user(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_user_existing)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->shell = "/bin/ksh";

    ret = test_store_user(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    ret = test_store_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store POSIX group #%d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    ret = test_remove_user(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_user_by_uid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->uid = _i;

    ret = test_remove_user_by_uid(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove user with uid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_remove_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_group_by_gid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    null_ctx_get_size(data->ctx);
    ret = test_remove_group_by_gid(data);
    fail_if_null_ctx_leaks(test_ctx);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove group with gid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_user(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group_with_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *member_fqname;
    int j;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    for (j = MBO_GROUP_BASE; j < _i; j++) {
        member_fqname = test_asprintf_fqname(data, data->ctx->domain,
                                             "testghost%d", j);
        ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, member_fqname);
        if (ret != EOK) {
            ck_assert_msg(ret == EOK, "Cannot add attr\n");
        }
    }

    ret = test_store_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_incomplete_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_incomplete_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add incomplete group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_incomplete_group_rename)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;

    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    ret = sysdb_add_incomplete_group(test_ctx->domain, "incomplete_group",
                                     20000, NULL,
                                     "S-1-5-21-123-456-789-111",
                                     NULL, true, 0);
    ck_assert_msg(ret == EOK,
                "sysdb_add_incomplete_group error [%d][%s]",
                ret, strerror(ret));

    /* Adding a group with the same GID and all the other characteristics unknown should succeed */
    ret = sysdb_add_incomplete_group(test_ctx->domain, "incomplete_group_new",
                                     20000, NULL, NULL, NULL, true, 0);
    ck_assert_msg(ret == ERR_GID_DUPLICATED,
                "Did not catch a rename. ret: %d [%s]",
                ret, sss_strerror(ret));

    /* A different SID should also succeed */
    ret = sysdb_add_incomplete_group(test_ctx->domain, "incomplete_group_new",
                                     20000, NULL,
                                     "S-1-5-21-123-456-789-222",
                                     NULL, true, 0);
    ck_assert_msg(ret == ERR_GID_DUPLICATED,
                "Did not catch a rename. ret: %d [%s]",
                ret, sss_strerror(ret));

    /* If we know based on a SID that the group is in fact the same,
     * let's just change its name
     */
    ret = sysdb_add_incomplete_group(test_ctx->domain, "incomplete_group_new",
                                     20000, NULL,
                                     "S-1-5-21-123-456-789-111",
                                     NULL, true, 0);
    ck_assert_msg(ret == ERR_GID_DUPLICATED,
                "Did not catch a rename. ret: %d [%s]",
                ret, sss_strerror(ret));
}
END_TEST

START_TEST (test_sysdb_getpwnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_result *res;
    uid_t uid;
    int ret;
    const char *username;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    res = test_getpwnam(data);
    sss_ck_fail_if_msg(res->count != 1,
            "Invalid number of replies. Expected 1, got %d", res->count);

    /* Check the user was found with the expected FQDN and UID */
    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    ck_assert_msg(uid == _i, "Did not find the expected UID");
    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_str_eq(username, data->username);

    /* Search for the user with the wrong case */
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "TESTUSER%d", _i);
    sss_ck_fail_if_msg(data->username == NULL, "OOM");

    res = test_getpwnam(data);
    sss_ck_fail_if_msg(res->count != 0,
            "Invalid number of replies. Expected 0, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_user_group_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_message *msg;
    int ret;
    const char *groupname;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    /* setup_sysdb_tests creates proxy(files) provider and we need to handle
     * ldap provider differently with auto_private_groups.
     */
    test_ctx->domain->provider = discard_const_p(char, "ldap");
    test_ctx->domain->mpg_mode = MPG_ENABLED;

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = sysdb_search_group_by_name(data,
                                     data->ctx->domain,
                                     data->username, /* we're searching for the private group */
                                     NULL,
                                     &msg);
    sss_ck_fail_if_msg(ret != EOK,
            "sysdb_search_group_by_name failed with error: %d", ret);
    sss_ck_fail_if_msg(msg == NULL, "Failed to find group: %s", data->username);

    groupname = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_str_eq(groupname, data->username);
}
END_TEST

START_TEST(test_user_group_by_name_local)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_message *msg;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = sysdb_search_group_by_name(data,
                                     data->ctx->domain,
                                     data->username, /* we're searching for the private group */
                                     NULL,
                                     &msg);
    sss_ck_fail_if_msg(ret != ENOENT,
            "sysdb_search_group_by_name must return ENOENT got: %d", ret);
}
END_TEST

START_TEST (test_sysdb_getgrnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_result *res;
    const char *groupname;
    gid_t gid;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    res = test_getgrnam(data);
    sss_ck_fail_if_msg(res->count != 1,
            "Invalid number of replies. Expected 1, got %d", res->count);

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    ck_assert_msg(gid == _i,
                "Did not find the expected GID (found %d expected %d)",
                gid, _i);
    groupname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_str_eq(groupname, data->groupname);

    /* Search for the group with the wrong case */
    data->groupname = test_asprintf_fqname(data, test_ctx->domain,
                                          "TESTGROUP%d", _i);
    sss_ck_fail_if_msg(data->groupname == NULL, "OOM");

    res = test_getgrnam(data);
    sss_ck_fail_if_msg(res->count != 0,
            "Invalid number of replies. Expected 1, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrgid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_result *res;
    const char *fqname;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    ret = sysdb_getgrgid(test_ctx,
                         test_ctx->domain,
                         data->gid, &res);
    if (ret) {
        ck_abort_msg("sysdb_getgrgid failed for gid %d (%d: %s)",
             data->gid, ret, strerror(ret));
        goto done;
    }

    fqname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);
    ck_assert_msg(fqname != NULL, "No group name?\n");

    ck_assert_msg(strcmp(fqname, data->groupname) == 0,
                "Did not find the expected groupname (found %s expected %s)",
                fqname, data->groupname);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrgid_attrs)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_result *res;
    int ret;
    const char *attrs[] = { SYSDB_CREATE_TIME, NULL };
    uint64_t ctime;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    ret = sysdb_getgrgid_attrs(test_ctx,
                               test_ctx->domain,
                               data->gid, attrs, &res);
    if (ret) {
        ck_abort_msg("sysdb_getgrgid_attrs failed for gid %d (%d: %s)",
             data->gid, ret, strerror(ret));
        goto done;
    }

    ctime = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_CREATE_TIME, 0);
    ck_assert_msg(ctime != 0, "Missing create time");

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_groups)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *attrs[] = { SYSDB_NAME, NULL };
    char *filter;
    size_t count;
    struct ldb_message **msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    filter = talloc_asprintf(test_ctx, "("SYSDB_GIDNUM"=%d)", _i);
    sss_ck_fail_if_msg(filter == NULL, "OOM");

    ret = sysdb_search_groups(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_free(filter);
    sss_ck_fail_if_msg(ret != EOK, "Search failed: %d", ret);
    sss_ck_fail_if_msg(count != 1, "Did not find the expected group\n");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_result *res;
    const char *fqname;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = sysdb_getpwuid(test_ctx,
                         test_ctx->domain,
                         _i, &res);
    if (ret) {
        ck_abort_msg("sysdb_getpwuid failed for uid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

    ck_assert_msg(res->count == 1, "Expected 1 user entry, found %d\n",
                res->count);

    fqname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);
    ck_assert_msg(fqname != NULL, "No name?\n");

    ck_assert_msg(strcmp(fqname, data->username) == 0,
                "Did not find the expected username (found %s expected %s)",
                fqname, data->username);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumgrent)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    test_ctx->domain->mpg_mode = MPG_ENABLED;

    ret = sysdb_enumgrent(test_ctx,
                          test_ctx->domain,
                          &res);
    ck_assert_msg(ret == EOK,
                "sysdb_enumgrent failed (%d: %s)",
                ret, strerror(ret));

    /* 10 groups + 10 users (we're MPG) */
    sss_ck_fail_if_msg(res->count != 20, "Expected 20 users, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumpwent)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    ret = sysdb_enumpwent(test_ctx,
                          test_ctx->domain,
                          &res);
    ck_assert_msg(ret == EOK,
                "sysdb_enumpwent failed (%d: %s)",
                ret, strerror(ret));

    sss_ck_fail_if_msg(res->count != 10, "Expected 10 users, got %d", res->count);

    talloc_free(test_ctx);
}
END_TEST


START_TEST (test_sysdb_set_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not create the changeset");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 SYSDB_SHELL,
                                 "/bin/ksh");
    if (ret != EOK) {
        ck_abort_msg("Could not create the changeset");
        return;
    }

    ret = test_set_user_attr(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not modify user %s", data->username);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_users)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *attrs[] = { SYSDB_NAME, NULL };
    char *filter;
    size_t count;
    struct ldb_message **msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    filter = talloc_asprintf(test_ctx,
                             "(&("SYSDB_UIDNUM"=%d)("SYSDB_SHELL"=/bin/ksh))",
                             _i);
    sss_ck_fail_if_msg(filter == NULL, "OOM");

    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_free(filter);
    sss_ck_fail_if_msg(ret != EOK, "Search failed: %d", ret);
    sss_ck_fail_if_msg(count != 1, "Did not find the expected user\n");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_attrs)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *rmattrs[2];
    struct ldb_result *res;
    const char *shell;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         data->username, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_getpwnam failed for fqname %s (%d: %s)",
                         data->username, ret, strerror(ret));
    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    ck_assert_msg(shell != NULL, "Did not find user shell before removal");

    rmattrs[0] = discard_const(SYSDB_SHELL);
    rmattrs[1] = NULL;

    ret = sysdb_remove_attrs(test_ctx->domain, data->username,
                             SYSDB_MEMBER_USER, rmattrs);
    sss_ck_fail_if_msg(ret != EOK, "Removing attributes failed: %d", ret);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         data->username, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_getpwnam failed for fqname %s (%d: %s)",
                         data->username, ret, strerror(ret));
    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    ck_assert_msg(shell == NULL, "Found user shell after removal");
}
END_TEST

START_TEST (test_sysdb_get_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    const char *attrs[] = { SYSDB_SHELL, NULL };
    struct ldb_result *res;
    const char *attrval;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, data->username, attrs,
                              &res);
    if (ret) {
        ck_abort_msg("Could not get attributes for user %s", data->username);
        goto done;
    }

    sss_ck_fail_if_msg(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, 0);
    sss_ck_fail_if_msg(strcmp(attrval, "/bin/ksh"),
            "Got bad attribute value for user %s", data->username);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_user_attr_subdomain)
{
    struct sysdb_test_ctx *test_ctx;
    struct sss_domain_info *subdomain = NULL;
    const char *attrs[] = { SYSDB_SHELL, NULL };
    struct ldb_result *res;
    const char *attrval;
    const char *username = "test_sysdb_get_user_attr_subdomain";
    const char *fq_name;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    /* Create subdomain */
    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              "test.sub", "TEST.SUB", "test", "test.sub", "S-3",
                              MPG_DISABLED, false, NULL, NULL, 0, IPA_TRUST_UNKNOWN, NULL, true);
    sss_ck_fail_if_msg(subdomain == NULL, "Failed to create new subdomain.");

    ret = sss_names_init_from_args(test_ctx,
                                   SSS_IPA_AD_DEFAULT_RE,
                                   "%1$s@%2$s", &subdomain->names);
    sss_ck_fail_if_msg(ret != EOK, "Failed to init names.");

    /* Create user */
    fq_name = sss_create_internal_fqname(test_ctx, username, subdomain->name);
    sss_ck_fail_if_msg(fq_name == NULL, "Failed to create fq name.");

    ret = sysdb_store_user(subdomain, fq_name, NULL, 12345, 0, "Gecos",
                           "/home/userhome", "/bin/bash", NULL, NULL, NULL,
                           -1, 0);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_store_user failed.");

    /* Test */
    ret = sysdb_get_user_attr(test_ctx, subdomain, fq_name,
                              attrs, &res);
    sss_ck_fail_if_msg(ret != EOK, "Could not get user attributes.");
    sss_ck_fail_if_msg(res->count != 1, "Invalid number of entries, expected 1, got %d",
            res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, 0);
    sss_ck_fail_if_msg(strcmp(attrval, "/bin/bash") != 0, "Got bad attribute value.");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_nonposix_user)
{
    struct sysdb_test_ctx *test_ctx;
    const char *get_attrs[] = { SYSDB_GIDNUM,
                                SYSDB_UIDNUM,
                                SYSDB_POSIX,
                                NULL };
    struct ldb_result *res;
    const char *attrval;
    const char *username = "test_sysdb_add_nonposix_user";
    const char *fq_name;
    struct sysdb_attrs *user_attrs;
    int ret;
    uint64_t id;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    /* Create user */
    fq_name = sss_create_internal_fqname(test_ctx, username, test_ctx->domain->name);
    sss_ck_fail_if_msg(fq_name == NULL, "Failed to create fq name.");

    user_attrs = sysdb_new_attrs(test_ctx);
    sss_ck_fail_if_msg(user_attrs == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_bool(user_attrs, SYSDB_POSIX, false);
    sss_ck_fail_if_msg(ret != EOK, "Could not add attribute");

    ret = sysdb_add_user(test_ctx->domain, fq_name, 0, 0, "Gecos",
                         "/home/userhome", "/bin/bash", NULL, user_attrs, 0, 0);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_add_user failed.");

    /* Test */
    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, fq_name,
                              get_attrs, &res);
    sss_ck_fail_if_msg(ret != EOK, "Could not get user attributes.");
    sss_ck_fail_if_msg(res->count != 1, "Invalid number of entries, expected 1, got %d",
            res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_POSIX, NULL);
    sss_ck_fail_if_msg(strcasecmp(attrval, "false") != 0, "Got bad attribute value.");

    id = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_UIDNUM, 123);
    ck_assert_msg(id == 0, "Wrong UID value");

    talloc_free(test_ctx);
}
END_TEST

static void add_nonposix_incomplete_group(struct sysdb_test_ctx *test_ctx,
                                          const char *groupname)
{
    const char *get_attrs[] = { SYSDB_GIDNUM,
                                SYSDB_POSIX,
                                NULL };
    struct ldb_message *msg;
    const char *attrval;
    const char *fq_name;
    int ret;

    /* Create group */
    fq_name = sss_create_internal_fqname(test_ctx, groupname, test_ctx->domain->name);
    sss_ck_fail_if_msg(fq_name == NULL, "Failed to create fq name.");

    ret = sysdb_add_incomplete_group(test_ctx->domain, fq_name, 0,
                                     NULL, NULL, NULL, false, 0);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_add_group failed.");

    /* Test */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain, fq_name, get_attrs, &msg);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_search_group_by_name failed.");

    attrval = ldb_msg_find_attr_as_string(msg, SYSDB_POSIX, NULL);
    sss_ck_fail_if_msg(strcasecmp(attrval, "false") != 0, "Got bad attribute value.");
}

START_TEST (test_sysdb_add_nonposix_group)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    add_nonposix_incomplete_group(test_ctx, "nonposix1");
    add_nonposix_incomplete_group(test_ctx, "nonposix2");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = _i - 1000; /* the UID of user to add */
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testuser%d", data->uid);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = test_add_group_member(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not modify group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_initgroups)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    struct ldb_result *res;
    struct ldb_message *user;
    struct ldb_message *group;
    gid_t gid;
    uid_t uid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM\n");

    ret = sysdb_initgroups(test_ctx,
                           test_ctx->domain,
                           data->username,
                           &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed\n");

    /* result should contain 2 messages - user and his group */
    sss_ck_fail_if_msg(res->count != 2, "expected 2 groups, got %d\n", res->count);

    /* check if it's the expected user and expected group */
    user = res->msgs[0];
    group = res->msgs[1];

    uid = ldb_msg_find_attr_as_uint(user, SYSDB_UIDNUM, 0);
    ck_assert_msg(uid == _i,
                "Did not find the expected UID (found %d expected %d)",
                uid, _i);

    ck_assert_msg(strcmp(ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL),
                       data->username) == 0,
                "Wrong username\n");

    gid = ldb_msg_find_attr_as_uint(group, SYSDB_GIDNUM, 0);
    ck_assert_msg(gid == _i + 1000,
                "Did not find the expected GID (found %d expected %d)",
                gid, _i);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = _i - 1000; /* the UID of user to remove */
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testuser%d", data->uid);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = test_remove_group_member(data);
    sss_ck_fail_if_msg(ret != EOK, "Remove group member failed: %d", ret);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->uid = 12345;

    ret = test_remove_user_by_uid(data);

    sss_ck_fail_if_msg(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->gid = 12345;

    ret = test_remove_group_by_gid(data);

    sss_ck_fail_if_msg(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = _i;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_VALUE);
    if (ret != EOK) {
        ck_abort_msg("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *object_name;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(test_ctx, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    ck_assert_msg(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data,
                                      data->ctx->domain,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    sss_ck_fail_if_msg(ret != EOK, "Could not search custom object");

    ck_assert_msg(data->msgs_count == 1,
                "Wrong number of objects, expected [1] got [%zd]",
                data->msgs_count);
    ck_assert_msg(data->msgs[0]->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msgs[0]->num_elements);
    ck_assert_msg(strcmp(data->msgs[0]->elements[0].name, TEST_ATTR_NAME) == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msgs[0]->elements[0].num_values == 1,
                "Wrong number of attribute values");
    ck_assert_msg(strncmp((const char *)data->msgs[0]->elements[0].values[0].data,
                        TEST_ATTR_VALUE,
                        data->msgs[0]->elements[0].values[0].length) == 0,
                "Wrong attribute value");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_update_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = 29010;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_UPDATE_VALUE);
    if (ret != EOK) {
        ck_abort_msg("Could not add attribute");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_ADD_NAME,
                                 TEST_ATTR_ADD_VALUE);
    if (ret != EOK) {
        ck_abort_msg("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom_update)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *object_name;
    struct ldb_message_element *el;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(test_ctx, const char *, 3);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    ck_assert_msg(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data,
                                      data->ctx->domain,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    sss_ck_fail_if_msg(ret != EOK, "Could not search custom object");

    ck_assert_msg(data->msgs_count == 1,
                "Wrong number of objects, expected [1] got [%zd]",
                data->msgs_count);
    ck_assert_msg(data->msgs[0]->num_elements == 2,
                "Wrong number of results, expected [2] got [%d]",
                data->msgs[0]->num_elements);

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_NAME);
    ck_assert_msg(el != NULL, "Attribute [%s] not found", TEST_ATTR_NAME);
    ck_assert_msg(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_NAME);
    ck_assert_msg(strncmp((const char *) el->values[0].data,
                TEST_ATTR_UPDATE_VALUE,
                el->values[0].length) == 0,
                "Wrong attribute value");

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_ADD_NAME);
    ck_assert_msg(el != NULL, "Attribute [%s] not found", TEST_ATTR_ADD_NAME);
    ck_assert_msg(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_ADD_NAME);
    ck_assert_msg(strncmp((const char *) el->values[0].data,
                TEST_ATTR_ADD_VALUE,
                el->values[0].length) == 0,
                "Wrong attribute value");


    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *filter = "(distinguishedName=*)";

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(test_ctx, const char *, 3);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    ret = sysdb_search_custom(data, data->ctx->domain, filter,
                              CUSTOM_TEST_CONTAINER,
                              data->attrlist,
                              &data->msgs_count,
                              &data->msgs);

    sss_ck_fail_if_msg(ret != EOK, "Could not search custom object");

    ck_assert_msg(data->msgs_count == 10,
                "Wrong number of objects, expected [10] got [%zd]",
                data->msgs_count);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_delete_custom)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_delete_custom(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not delete custom object");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_cache_password)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM\n");

    ret = sysdb_cache_password(test_ctx->domain,
                               data->username,
                               data->username);
    ck_assert_msg(ret == EOK, "sysdb_cache_password request failed [%d].", ret);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_cache_password_ex)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    struct ldb_result *res;
    const char *attrs[] = { SYSDB_CACHEDPWD_TYPE, SYSDB_CACHEDPWD_FA2_LEN,
                            NULL };
    int val;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "OOM\n");

    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, data->username,
                              attrs, &res);
    ck_assert_msg(ret == EOK, "sysdb_get_user_attr request failed [%d].", ret);

    val = ldb_msg_find_attr_as_int(res->msgs[0], SYSDB_CACHEDPWD_TYPE, 0);
    ck_assert_msg(val == SSS_AUTHTOK_TYPE_PASSWORD,
                "Unexpected authtok type, found [%d], expected [%d].",
                val, SSS_AUTHTOK_TYPE_PASSWORD);

    ret = sysdb_cache_password_ex(test_ctx->domain, data->username,
                                  data->username, SSS_AUTHTOK_TYPE_2FA, 12);

    ck_assert_msg(ret == EOK, "sysdb_cache_password request failed [%d].", ret);

    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, data->username,
                              attrs, &res);
    ck_assert_msg(ret == EOK, "sysdb_get_user_attr request failed [%d].", ret);

    val = ldb_msg_find_attr_as_int(res->msgs[0], SYSDB_CACHEDPWD_TYPE, 0);
    ck_assert_msg(val == SSS_AUTHTOK_TYPE_2FA,
                "Unexpected authtok type, found [%d], expected [%d].",
                val, SSS_AUTHTOK_TYPE_2FA);

    val = ldb_msg_find_attr_as_int(res->msgs[0], SYSDB_CACHEDPWD_FA2_LEN, 0);
    ck_assert_msg(val == 12,
                "Unexpected second factor length, found [%d], expected [%d].",
                val, 12);

    talloc_free(test_ctx);
}
END_TEST

static void cached_authentication_without_expiration(uid_t uid,
                                                     const char *password,
                                                     int expected_result)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    time_t expire_date = -1;
    time_t delayed_until = -1;
    const char *val[2];
    val[1] = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, uid);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    val[0] = "0";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    ret = sysdb_cache_auth(test_ctx->domain, data->username,
                           password ? password : data->username,
                           test_ctx->confdb, false,
                           &expire_date, &delayed_until);

    ck_assert_msg(ret == expected_result, "sysdb_cache_auth request does not "
                                        "return expected result [%d].",
                                        expected_result);

    ck_assert_msg(expire_date == 0, "Wrong expire date, expected [%d], got [%"SPRItime"]",
                                  0, expire_date);

    ck_assert_msg(delayed_until == -1, "Wrong delay, expected [%d], got [%"SPRItime"]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

static void cached_authentication_with_expiration(uid_t uid,
                                                  const char *password,
                                                  int expected_result)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    time_t expire_date = -1;
    const char *val[2];
    val[1] = NULL;
    time_t now;
    time_t expected_expire_date;
    time_t delayed_until = -1;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, uid);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    val[0] = "1";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        ck_abort_msg("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    now = time(NULL);
    expected_expire_date = now + (24 * 60 * 60);
    DEBUG(SSSDBG_TRACE_ALL,
          "Setting SYSDB_LAST_ONLINE_AUTH to [%lld].\n", (long long) now);

    data->attrs = sysdb_new_attrs(data);
    ret = sysdb_attrs_add_time_t(data->attrs, SYSDB_LAST_ONLINE_AUTH, now);
    ck_assert_msg(ret == EOK, "Could not add attribute "SYSDB_LAST_ONLINE_AUTH
                            ": %s", sss_strerror(ret));

    ret = sysdb_set_user_attr(data->ctx->domain, data->username, data->attrs,
                              SYSDB_MOD_REP);
    ck_assert_msg(ret == EOK, "Could not modify user %s", data->username);

    ret = sysdb_cache_auth(data->ctx->domain, data->username,
                           password ? password : data->username,
                           test_ctx->confdb, false,
                           &expire_date, &delayed_until);

    ck_assert_msg(ret == expected_result,
                "sysdb_cache_auth request does not return expected "
                "result [%d], got [%d].", expected_result, ret);

    ck_assert_msg(expire_date == expected_expire_date,
                "Wrong expire date, expected [%"SPRItime"], got [%"SPRItime"]",
                expected_expire_date, expire_date);

    ck_assert_msg(delayed_until == -1, "Wrong delay, expected [%d], got [%"SPRItime"]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

START_TEST (test_sysdb_cached_authentication_missing_password)
{
    cached_authentication_without_expiration(_i, "abc", ERR_NO_CACHED_CREDS);
    cached_authentication_with_expiration(_i, "abc", ERR_NO_CACHED_CREDS);
}
END_TEST

START_TEST (test_sysdb_cached_authentication_wrong_password)
{
    cached_authentication_without_expiration(_i, "abc", ERR_AUTH_FAILED);
    cached_authentication_with_expiration(_i, "abc", ERR_AUTH_FAILED);
}
END_TEST

START_TEST (test_sysdb_cached_authentication)
{
    cached_authentication_without_expiration(_i, NULL, EOK);
    cached_authentication_with_expiration(_i, NULL, EOK);
}
END_TEST

START_TEST (test_sysdb_prepare_asq_test_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = ASQ_TEST_USER_UID;
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testuser%u", data->uid);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = test_add_group_member(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not modify group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_asq_search)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_dn *user_dn;
    int ret;
    size_t msgs_count;
    struct ldb_message **msgs;
    int i;
    char *gid_str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, ASQ_TEST_USER_UID);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = "gidNumber";
    data->attrlist[1] = NULL;

    user_dn = sysdb_user_dn(data, data->ctx->domain, data->username);
    ck_assert_msg(user_dn != NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(data, test_ctx->domain,
                           user_dn, NULL, "memberof",
                           data->attrlist, &msgs_count, &msgs);

    sss_ck_fail_if_msg(ret != EOK, "Failed to send ASQ search request.\n");

    ck_assert_msg(msgs_count == 10, "wrong number of results, "
                                  "found [%zd] expected [10]", msgs_count);

    for (i = 0; i < msgs_count; i++) {
        ck_assert_msg(msgs[i]->num_elements == 1, "wrong number of elements, "
                                     "found [%d] expected [1]",
                                     msgs[i]->num_elements);

        ck_assert_msg(msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    msgs[i]->elements[0].num_values);

        gid_str = talloc_asprintf(data, "%d", 28010 + i);
        ck_assert_msg(gid_str != NULL, "talloc_asprintf failed.");
        ck_assert_msg(strncmp(gid_str,
                            (const char *) msgs[i]->elements[0].values[0].data,
                            msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            (int) msgs[i]->elements[0].values[0].length,
                            msgs[i]->elements[0].values[0].data, gid_str);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_all_users)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    int i;
    int j;
    char *uid_str = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    ck_assert_msg(data != NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = "uidNumber";
    data->attrlist[1] = NULL;

    ret = test_search_all_users(data);

    sss_ck_fail_if_msg(ret != EOK, "Search failed");

    ck_assert_msg(data->msgs_count == 10,
                "wrong number of results, found [%zd] expected [10]",
                data->msgs_count);

    for (i = 0; i < data->msgs_count; i++) {
        ck_assert_msg(data->msgs[i]->num_elements == 1,
                    "wrong number of elements, found [%d] expected [1]",
                    data->msgs[i]->num_elements);

        ck_assert_msg(data->msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    data->msgs[i]->elements[0].num_values);

        for (j = 0; j < data->msgs_count; j++) {
            uid_str = talloc_asprintf(data, "%d", 27010 + j);
            ck_assert_msg(uid_str != NULL, "talloc_asprintf failed.");
            if (strncmp(uid_str,
                        (char *) data->msgs[i]->elements[0].values[0].data,
                        data->msgs[i]->elements[0].values[0].length)  == 0) {
                break;
            }
        }
        ck_assert_msg(strncmp(uid_str,
                            (char *) data->msgs[i]->elements[0].values[0].data,
                            data->msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            (int) data->msgs[i]->elements[0].values[0].length,
                            data->msgs[i]->elements[0].values[0].data, uid_str);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_delete_recursive)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    ck_assert_msg(data != NULL, "Failed to allocate memory");

    ret = test_delete_recursive(data);

    sss_ck_fail_if_msg(ret != EOK, "Recursive delete failed");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_attrs_replace_name)
{
    struct sysdb_attrs *attrs;
    struct ldb_message_element *el;
    int ret;

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, "foo", "bar");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "fool", "bool");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "foot", "boot");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_replace_name(attrs, "foo", "foot");
    ck_assert_msg(ret == EEXIST,
                "sysdb_attrs_replace overwrites existing attribute");

    ret = sysdb_attrs_replace_name(attrs, "foo", "oof");
    ck_assert_msg(ret == EOK, "sysdb_attrs_replace failed");

    ret = sysdb_attrs_get_el(attrs, "foo", &el);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_el failed");
    ck_assert_msg(el->num_values == 0, "Attribute foo is not empty.");

    ret = sysdb_attrs_get_el(attrs, "oof", &el);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_el failed");
    ck_assert_msg(el->num_values == 1,
                "Wrong number of values for attribute oof, "
                "expected [1] got [%d].", el->num_values);
    ck_assert_msg(strncmp("bar", (char *) el->values[0].data,
                        el->values[0].length) == 0,
                "Wrong value, expected [bar] got [%.*s]",
                (int)  el->values[0].length, el->values[0].data);

    talloc_free(attrs);
}
END_TEST

START_TEST (test_sysdb_memberof_store_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE + _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = test_asprintf_fqname(data, data->ctx->domain,
                                                 "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
        sss_ck_fail_if_msg(data->attrlist[0] == NULL, "Failed to allocate memory");
    }

    ret = test_memberof_store_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_store_group_with_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    if (_i == 0 || _i == MBO_GROUP_BASE) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = test_asprintf_fqname(data, data->ctx->domain,
                                                 "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
        sss_ck_fail_if_msg(data->attrlist[0] == NULL, "Failed to allocate memory");
    }

    data->ghostlist = talloc_array(data, char *, 2);
    ck_assert_msg(data->ghostlist != NULL, "talloc_array failed.");
    data->ghostlist[0] = test_asprintf_fqname(data, data->ctx->domain,
                                             "testuser%d", data->gid);
    data->ghostlist[1] = NULL;
    sss_ck_fail_if_msg(data->ghostlist[0] == NULL, "Failed to allocate memory");

    ret = test_memberof_store_group_with_ghosts(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_store_group_with_double_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = test_asprintf_fqname(data, data->ctx->domain,
                                                 "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
    }

    data->ghostlist = talloc_array(data, char *, 3);
    ck_assert_msg(data->ghostlist != NULL, "talloc_array failed.");
    data->ghostlist[0] = test_asprintf_fqname(data, data->ctx->domain,
                                              "testusera%d", data->gid);
    data->ghostlist[1] = test_asprintf_fqname(data, data->ctx->domain,
                                              "testuserb%d", data->gid);
    data->ghostlist[2] = NULL;

    ret = test_memberof_store_group_with_ghosts(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_mod_add)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;
    gid_t itergid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ghostname = test_asprintf_fqname(data, test_ctx->domain,
                                     "testghost%d", _i);
    ck_assert_msg(ghostname != NULL, "Out of memory\n");

    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the add, the groups should not contain the ghost attribute */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        if (data->gid > MBO_GROUP_BASE) {
            /* The first group would have the ghost attribute gone completely */
            sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");
            test_gv = ldb_msg_find_val(el, &gv);
            ck_assert_msg(test_gv == NULL,
                        "Ghost user %s unexpectedly found\n", ghostname);
        } else {
            ck_assert_msg(el == NULL, "Stray values in ghost element?\n");
        }
    }

    /* Perform the add operation */
    ret = sysdb_set_group_attr(test_ctx->domain,
                               data->groupname, data->attrs, SYSDB_MOD_ADD);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* Before the delete, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname);
    }
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_mod_replace)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname_del;
    char *ghostname_add;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;
    gid_t itergid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    /* The test replaces the testuser%i attribute with testghost%i */
    ghostname_del = test_asprintf_fqname(data, test_ctx->domain,
                                         "testuser%d", _i);
    ck_assert_msg(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = test_asprintf_fqname(data, test_ctx->domain,
                                         "testuser%d", _i);
    ck_assert_msg(ghostname_add != NULL, "Out of memory\n");

    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_del);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);
    }

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, all groups with gid >= _i have the testghost%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_add;
        gv.length = strlen(ghostname_add);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_mod_replace_keep)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname_rep;
    char *ghostname_del;
    char *ghostname_check;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;
    gid_t itergid;
    uid_t iteruid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE + 10 - _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    /* The test replaces the attributes (testusera$gid, testuserb$gid) with
     * just testusera$gid. The result should be not only testusera, but also
     * all ghost users inherited from child groups
     */
    ghostname_rep = test_asprintf_fqname(data, data->ctx->domain,
                                         "testusera%d", data->gid);
    ck_assert_msg(ghostname_rep != NULL, "Out of memory\n");

    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_rep);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    ghostname_del = test_asprintf_fqname(data, data->ctx->domain,
                                         "testuserb%d", data->gid);
    ck_assert_msg(ghostname_del != NULL, "Out of memory\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, all groups with gid >= _i have both testuser a
     * and testuserb as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_rep;
        gv.length = strlen(ghostname_rep);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_rep);

        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_rep);

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

        /* inherited users must be there */
        for (iteruid = MBO_GROUP_BASE ; iteruid < itergid ; iteruid++) {
            ghostname_check = test_asprintf_fqname(data, data->ctx->domain,
                                                   "testusera%d", iteruid);
            ck_assert_msg(ghostname_rep != NULL, "Out of memory\n");

            gv.data = (uint8_t *) ghostname_check;
            gv.length = strlen(ghostname_check);

            test_gv = ldb_msg_find_val(el, &gv);
            sss_ck_fail_if_msg(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                    ghostname_check);

            if (iteruid < data->gid) {
                /* Also check the B user if it hasn't been deleted yet */
                ghostname_check = test_asprintf_fqname(data, data->ctx->domain,
                                                       "testuserb%d", iteruid);
                gv.data = (uint8_t *) ghostname_check;
                gv.length = strlen(ghostname_check);

                test_gv = ldb_msg_find_val(el, &gv);
                sss_ck_fail_if_msg(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                        ghostname_check);
            }
            talloc_zfree(ghostname_check);
        }
    }

    /* Perform the replace operation */
    ret = sysdb_set_group_attr(test_ctx->domain,
                               data->groupname, data->attrs, SYSDB_MOD_REP);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, testusera should still be there, but we also need
     * to keep ghost users inherited from other groups
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_rep;
        gv.length = strlen(ghostname_rep);

        /* testusera must still be there */
        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_rep);

        /* testuserb must be gone */
        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_rep);

        test_gv = ldb_msg_find_val(el, &gv);
        ck_assert_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

        /* inherited users must still be there */
        for (iteruid = MBO_GROUP_BASE ; iteruid < itergid ; iteruid++) {
            ghostname_check = test_asprintf_fqname(data, data->ctx->domain,
                                                   "testusera%d", iteruid);
            gv.data = (uint8_t *) ghostname_check;
            gv.length = strlen(ghostname_check);

            test_gv = ldb_msg_find_val(el, &gv);
            sss_ck_fail_if_msg(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                    ghostname_check);

            if (iteruid < data->gid) {
                /* Also check the B user if it hasn't been deleted yet */
                ghostname_check = test_asprintf_fqname(data, data->ctx->domain,
                                                       "testuserb%d", iteruid);
                gv.data = (uint8_t *) ghostname_check;
                gv.length = strlen(ghostname_check);

                test_gv = ldb_msg_find_val(el, &gv);
                sss_ck_fail_if_msg(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                        ghostname_check);
            }
            talloc_zfree(ghostname_check);
        }
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_close_loop)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE);
    sss_ck_fail_if_msg(data == NULL, "OOM");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = test_asprintf_fqname(data, test_ctx->domain,
                                             "testgroup%d", data->gid + 9);
    ck_assert_msg(data->attrlist[0] != NULL, "talloc_array failed.");
    data->attrlist[1] = NULL;

    ret = test_memberof_store_group(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not store POSIX group #%d", data->gid);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, MBO_USER_BASE + _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_store_user(data);
    sss_ck_fail_if_msg(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_add_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE + _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->uid = MBO_USER_BASE + _i;
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testuser%d", data->uid);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = test_add_group_member(data);
    sss_ck_fail_if_msg(ret != EOK, "Could not modify group %s", data->groupname);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_without_group_5)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE + _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    data->gid, data->attrlist,
                                    &data->msg);
    if (_i == 5) {
        ck_assert_msg(ret == ENOENT,
                    "sysdb_search_group_by_gid found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);
    } else {
        sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

        ck_assert_msg(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        ck_assert_msg(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        ck_assert_msg(data->msg->elements[0].num_values == ((_i + 1) % 6),
                    "Wrong number of attribute values, "
                    "expected [%d] got [%d]", ((_i + 1) % 6),
                    data->msg->elements[0].num_values);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, MBO_GROUP_BASE + _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    data->gid, data->attrlist,
                                    &data->msg);

    sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

    ck_assert_msg(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    ck_assert_msg(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msg->elements[0].num_values == _i + 1,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i + 1, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_loop)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i + MBO_GROUP_BASE);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    data->gid, data->attrlist,
                                    &data->msg);

    sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

    ck_assert_msg(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    ck_assert_msg(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msg->elements[0].num_values == 10,
                "Wrong number of attribute values, expected [%d] got [%d]",
                10, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_memberuid_loop_without_group_5)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i + MBO_GROUP_BASE);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    data->gid, data->attrlist,
                                    &data->msg);

    if (_i == 5) {
        ck_assert_msg(ret == ENOENT,
                    "sysdb_search_group_by_gid_send found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);
    } else {
        sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

        ck_assert_msg(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        ck_assert_msg(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        ck_assert_msg(data->msg->elements[0].num_values == ((_i + 5) % 10),
                    "Wrong number of attribute values, expected [%d] got [%d]",
                    ((_i + 5) % 10), data->msg->elements[0].num_values);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_nested_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    ck_assert_msg(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msg->elements[0].num_values == _i - MBO_GROUP_BASE + 1,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i - MBO_GROUP_BASE + 1, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_nested_double_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    ck_assert_msg(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msg->elements[0].num_values == (_i - MBO_GROUP_BASE + 1)*2,
                "Wrong number of attribute values, expected [%d] got [%d]",
                (_i - MBO_GROUP_BASE + 1)*2,
                data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_remove_child_group_and_check_ghost)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    gid_t delgid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    delgid = data->gid - 1;

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    ck_assert_msg(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");

    /* Expect our own and our parent's */
    ck_assert_msg(data->msg->elements[0].num_values == 2,
                "Wrong number of attribute values, expected [%d] got [%d]",
                2, data->msg->elements[0].num_values);

    /* Remove the parent */
    ret = sysdb_delete_group(data->ctx->domain, NULL, delgid);
    sss_ck_fail_if_msg(ret != EOK, "Cannot delete group %llu [%d]: %s\n",
            (unsigned long long) data->gid, ret, strerror(ret));

    talloc_free(data->msg);

    /* Check the parent again. The inherited ghost user should be gone. */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    ck_assert_msg(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");

    /* Expect our own now only */
    ck_assert_msg(data->msg->elements[0].num_values == 1,
                "Wrong number of attribute values, expected [%d] got [%d]",
                1, data->msg->elements[0].num_values);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_mod_del)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;
    gid_t itergid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ghostname = test_asprintf_fqname(data, test_ctx->domain, "testuser%d", _i);
    ck_assert_msg(ghostname != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the delete, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname);
    }

    /* Delete the attribute */
    null_ctx_get_size(test_ctx);
    ret = sysdb_set_group_attr(test_ctx->domain,
                               data->groupname, data->attrs, SYSDB_MOD_DEL);
    fail_if_null_ctx_leaks(test_ctx);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* After the delete, we shouldn't be able to find the ghost attribute */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        if (itergid > data->gid) {
            /* The first group would have the ghost attribute gone completely */
            sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");
            test_gv = ldb_msg_find_val(el, &gv);
            ck_assert_msg(test_gv == NULL,
                        "Ghost user %s unexpectedly found\n", ghostname);
        } else {
            ck_assert_msg(el == NULL, "Stray values in ghost element?\n");
        }
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_check_ghost)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret, j;
    char *expected;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);

    sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

    if (_i > MBO_GROUP_BASE) {
        /* After the previous test, the first group (gid == MBO_GROUP_BASE)
         * has no ghost users. That's a legitimate test case we need to account
         * for now.
         */
        ck_assert_msg(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d] for %d",
                    data->msg->num_elements, data->gid);
    }

    if (data->msg->num_elements == 0) {
        talloc_free(test_ctx);
        return;
    }

    ck_assert_msg(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    ck_assert_msg(data->msg->elements[0].num_values == _i - MBO_GROUP_BASE,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i + 1, data->msg->elements[0].num_values);

    for (j = MBO_GROUP_BASE; j < _i; j++) {
        expected = test_asprintf_fqname(data, test_ctx->domain, "testghost%d", j);
        sss_ck_fail_if_msg(expected == NULL, "OOM\n");
        ck_assert_msg(strcmp(expected,
                           (const char *) data->msg->elements[0].values[j-MBO_GROUP_BASE].data) == 0,
                    "Expecting: %s dot: %s", expected,
                    (const char *) data->msg->elements[0].values[j-MBO_GROUP_BASE].data);
        talloc_free(expected);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_convert_to_real_users)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i * 2);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->username = test_asprintf_fqname(data, test_ctx->domain,
                                          "testghost%d", _i);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = test_store_user(data);
    sss_ck_fail_if_msg(ret != EOK, "Cannot add user %s\n", data->username);
}
END_TEST

START_TEST (test_sysdb_memberof_check_convert)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    struct ldb_message_element *ghosts;
    struct ldb_message_element *members;
    int exp_mem, exp_gh;

    /* Explicitly disable enumeration during setup as converting the ghost
     * users into real ones works only when enumeration is disabled
     */
    ret = _setup_sysdb_tests(&test_ctx, false);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->attrlist = talloc_array(data, const char *, 3);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = SYSDB_MEMBER;
    data->attrlist[2] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);

    sss_ck_fail_if_msg(ret != EOK, "Could not check group %d", data->gid);

    ck_assert_msg(data->msg->num_elements == (_i == MBO_GROUP_BASE) ? 0 : 1,
                "Wrong number of results, expected [1] got [%d] for %d",
                data->msg->num_elements, data->gid);

    if (data->msg->num_elements == 0) {
        talloc_free(test_ctx);
        return;
    }

    members = ldb_msg_find_element(data->msg, SYSDB_MEMBER);
    exp_mem = _i - MBO_GROUP_BASE;
    if (exp_mem > NUM_GHOSTS/2) {
        exp_mem = NUM_GHOSTS/2;
    }

    ghosts = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    exp_gh = _i - MBO_GROUP_BASE - 5;
    if (exp_gh < 0) {
        exp_gh = 0;
    }

    sss_ck_fail_if_msg(exp_mem != members->num_values,
            "Expected %d members, found %d\n", exp_mem, members->num_values);
    if (exp_gh) {
        sss_ck_fail_if_msg(exp_gh != ghosts->num_values,
                "Expected %d members, found %d\n", exp_gh, ghosts->num_values);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_memberof_ghost_replace)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname_del;
    char *ghostname_add;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    /* The test replaces the testghost%i attribute with testuser%i */
    ghostname_del = test_asprintf_fqname(data, test_ctx->domain,
                                         "testghost%d", data->gid - 1);
    ck_assert_msg(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = test_asprintf_fqname(data, test_ctx->domain,
                                         "testuser%d", data->gid - 1);
    ck_assert_msg(ghostname_add != NULL, "Out of memory\n");

    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_del;
    gv.length = strlen(ghostname_del);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_add;
    gv.length = strlen(ghostname_add);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
}
END_TEST

START_TEST (test_sysdb_memberof_ghost_replace_noop)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    char *ghostname_del;
    char *ghostname_add;
    int ret;
    struct ldb_message_element *el;
    struct ldb_val gv, *test_gv;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    /* The test replaces the testghost%i attribute with testuser%i */
    ghostname_del = test_asprintf_fqname(data, test_ctx->domain,
                                         "testuser%d", data->gid - 1);
    ck_assert_msg(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = test_asprintf_fqname(data, test_ctx->domain,
                                         "testuser%d", data->gid - 1);
    ck_assert_msg(ghostname_add != NULL, "Out of memory\n");

    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    ck_assert_msg(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    ck_assert_msg(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_del;
    gv.length = strlen(ghostname_del);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    ck_assert_msg(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    sss_ck_fail_if_msg(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_add;
    gv.length = strlen(ghostname_add);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    sss_ck_fail_if_msg(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    sss_ck_fail_if_msg(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
}
END_TEST

START_TEST (test_sysdb_memberof_user_cleanup)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_user(test_ctx, _i * 2);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_remove_user_by_uid(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove user with uid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_set_get_bool)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_dn *dn, *ne_dn;
    bool value;
    int ret;
    const char *attr_val = "BOOL_VALUE";

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    dn = sysdb_domain_dn(test_ctx, test_ctx->domain);
    ck_assert_msg(dn != NULL, "Failed to allocate memory");

    /* attribute is not created yet */
    ret = sysdb_get_bool(test_ctx->sysdb, dn, attr_val,
                         &value);
    ck_assert_msg(ret == ENOENT,
                "sysdb_get_bool returned %d:[%s], but ENOENT is expected",
                ret, sss_strerror(ret));

    /* add attribute */
    ret = sysdb_set_bool(test_ctx->sysdb, dn, test_ctx->domain->name,
                         attr_val, true);
    ck_assert_msg(ret == EOK, "sysdb_set_bool failed with error: %d", ret);

    /* successfully obtain attribute */
    ret = sysdb_get_bool(test_ctx->sysdb, dn, attr_val,
                         &value);
    ck_assert_msg(ret == EOK, "sysdb_get_bool failed %d:[%s]",
                ret, sss_strerror(ret));
    ck_assert_msg(value == true, "sysdb_get_bool must return true");

    /* use non-existing DN */
    ne_dn = ldb_dn_new_fmt(test_ctx, test_ctx->sysdb->ldb, SYSDB_DOM_BASE,
                        "non-existing domain");
    ck_assert_msg(ne_dn != NULL, "Failed to allocate memory");
    ret = sysdb_get_bool(test_ctx->sysdb, ne_dn, attr_val,
                         &value);
    ck_assert_msg(ret == ENOENT,
                "sysdb_get_bool returned %d:[%s], but ENOENT is expected",
                ret, sss_strerror(ret));

    /* free ctx */
    talloc_free(test_ctx);
}
END_TEST


START_TEST (test_sysdb_set_get_uint)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_dn *dn, *ne_dn;
    uint32_t value;
    int ret;
    const char *attr_val = "UINT_VALUE";

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    dn = sysdb_domain_dn(test_ctx, test_ctx->domain);
    ck_assert_msg(dn != NULL, "Failed to allocate memory");

    /* attribute is not created yet */
    ret = sysdb_get_uint(test_ctx->sysdb, dn, attr_val,
                         &value);
    ck_assert_msg(ret == ENOENT,
                "sysdb_get_uint returned %d:[%s], but ENOENT is expected",
                ret, sss_strerror(ret));

    /* add attribute */
    ret = sysdb_set_uint(test_ctx->sysdb, dn, test_ctx->domain->name,
                         attr_val, 0xCAFEBABE);
    ck_assert_msg(ret == EOK, "sysdb_set_uint failed with error: %d", ret);

    /* successfully obtain attribute */
    ret = sysdb_get_uint(test_ctx->sysdb, dn, attr_val,
                         &value);
    ck_assert_msg(ret == EOK, "sysdb_get_uint failed %d:[%s]",
                ret, sss_strerror(ret));
    ck_assert_int_eq(value, 0xCAFEBABE);

    /* use non-existing DN */
    ne_dn = ldb_dn_new_fmt(test_ctx, test_ctx->sysdb->ldb, SYSDB_DOM_BASE,
                        "non-existing domain");
    ck_assert_msg(ne_dn != NULL, "Failed to allocate memory");
    ret = sysdb_get_uint(test_ctx->sysdb, ne_dn, attr_val,
                         &value);
    ck_assert_msg(ret == ENOENT,
                "sysdb_get_uint returned %d:[%s], but ENOENT is expected",
                ret, sss_strerror(ret));

    /* free ctx */
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_attrs_to_list)
{
    struct sysdb_attrs *attrs_list[3];
    char **list;
    errno_t ret;

    TALLOC_CTX *test_ctx = talloc_new(NULL);

    attrs_list[0] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[0], "test_attr", "attr1");
    sss_ck_fail_if_msg(ret, "Add string failed");
    attrs_list[1] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[1], "test_attr", "attr2");
    sss_ck_fail_if_msg(ret, "Add string failed");
    attrs_list[2] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[2], "nottest_attr", "attr3");
    sss_ck_fail_if_msg(ret, "Add string failed");

    ret = sysdb_attrs_to_list(test_ctx, attrs_list, 3,
                              "test_attr", &list);
    ck_assert_msg(ret == EOK, "sysdb_attrs_to_list failed with code %d", ret);

    ck_assert_msg(strcmp(list[0],"attr1") == 0, "Expected [attr1], got [%s]",
                                              list[0]);
    ck_assert_msg(strcmp(list[1],"attr2") == 0, "Expected [attr2], got [%s]",
                                              list[1]);
    ck_assert_msg(list[2] == NULL, "List should be NULL-terminated");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_get_real_name)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct sysdb_attrs *user_attrs;
    const char *str;
    char *fq_alias;
    char *realname;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    fq_alias = sss_create_internal_fqname(test_ctx, "alias",
                                          test_ctx->domain->name);
    realname = sss_create_internal_fqname(test_ctx, "RealName",
                                          test_ctx->domain->name);
    sss_ck_fail_if_msg(fq_alias == NULL, "sss_create_internal_fqname failed");
    sss_ck_fail_if_msg(realname == NULL, "sss_create_internal_fqname failed");

    user_attrs = sysdb_new_attrs(test_ctx);
    ck_assert_msg(user_attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(user_attrs, SYSDB_NAME_ALIAS, fq_alias);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_attrs_add_string(user_attrs, SYSDB_UPN, "foo@bar");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_attrs_add_string(user_attrs, SYSDB_SID_STR,
                                 "S-1-5-21-123-456-789-111");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_attrs_add_string(user_attrs, SYSDB_UUID,
                                 "12345678-9012-3456-7890-123456789012");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_user(test_ctx->domain, realname,
                           NULL, 22345, 0, "gecos",
                           "/home/realname", "/bin/bash",
                           NULL, user_attrs, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "sysdb_store_user failed.");

    /* Get real, uncanonicalized name as string */
    ret = sysdb_get_real_name(test_ctx, test_ctx->domain, fq_alias, &str);
    ck_assert_msg(ret == EOK, "sysdb_get_real_name failed.");
    ck_assert_msg(strcmp(str, realname) == 0, "Expected [%s], got [%s].",
                                              realname, str);

    ret = sysdb_get_real_name(test_ctx, test_ctx->domain, "foo@bar", &str);
    ck_assert_msg(ret == EOK, "sysdb_get_real_name failed.");
    ck_assert_msg(strcmp(str, realname) == 0, "Expected [%s], got [%s].",
                                              realname, str);

    ret = sysdb_get_real_name(test_ctx, test_ctx->domain,
                              "S-1-5-21-123-456-789-111", &str);
    ck_assert_msg(ret == EOK, "sysdb_get_real_name failed.");
    ck_assert_msg(strcmp(str, realname) == 0, "Expected [%s], got [%s].",
                                              realname, str);

    ret = sysdb_get_real_name(test_ctx, test_ctx->domain,
                              "12345678-9012-3456-7890-123456789012", &str);
    ck_assert_msg(ret == EOK, "sysdb_get_real_name failed.");
    ck_assert_msg(strcmp(str, realname) == 0, "Expected [%s], got [%s].",
                                              realname, str);
}
END_TEST

START_TEST(test_group_rename)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    gid_t gid;
    const gid_t grgid = 38001;
    const char *name;
    char *fromname;
    char *toname;
    struct ldb_result *res;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    fromname = sss_create_internal_fqname(test_ctx, "fromgroup",
                                          test_ctx->domain->name);
    sss_ck_fail_if_msg(fromname == NULL, "sss_create_internal_fqname failed");
    toname = sss_create_internal_fqname(test_ctx, "togroup",
                                        test_ctx->domain->name);
    sss_ck_fail_if_msg(toname == NULL, "sss_create_internal_fqname failed");

    /* Store and verify the first group */
    ret = sysdb_store_group(test_ctx->domain,
                            fromname, grgid, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "Could not add first group");

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, fromname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the group from cache\n");
    if (res->count != 1) {
        ck_abort_msg("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    ck_assert_msg(gid == grgid,
                "Did not find the expected GID (found %llu expected %llu)",
                (unsigned long long) gid, (unsigned long long) grgid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(fromname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Perform rename and check that GID is the same, but name changed */
    ret = sysdb_add_group(test_ctx->domain, toname, grgid, NULL, 0, 0);
    ck_assert_msg(ret == EEXIST, "Group renamed with a low level call?");

    ret = sysdb_store_group(test_ctx->domain,
                            toname, grgid, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "Could not add first group");

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, toname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the group from cache\n");
    if (res->count != 1) {
        ck_abort_msg("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    ck_assert_msg(gid == grgid,
                "Did not find the expected GID (found %llu expected %llu)",
                (unsigned long long) gid, (unsigned long long) grgid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(toname, name) == 0,
                "Did not find the expected GID (found %s expected %s)",
                name, toname);

    /* Verify the first name is gone */
    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, fromname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the group from cache\n");
    ck_assert_msg(res->count == 0, "Unexpectedly found the original user\n");

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_user_rename)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    uid_t uid;
    const uid_t userid = 38002;
    const char *name;
    char *fromname;
    char *toname;
    struct ldb_result *res;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    fromname = sss_create_internal_fqname(test_ctx, "fromname", test_ctx->domain->name);
    toname = sss_create_internal_fqname(test_ctx, "toname", test_ctx->domain->name);
    sss_ck_fail_if_msg(fromname == NULL, "sss_create_internal_fqname failed");
    sss_ck_fail_if_msg(toname == NULL, "sss_create_internal_fqname failed");

    /* Store and verify the first user */
    ret = sysdb_store_user(test_ctx->domain,
                           fromname, NULL, userid, 0,
                           fromname, "/", "/bin/sh",
                           NULL, NULL, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "Could not add first user");

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, fromname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the user from cache\n");
    if (res->count != 1) {
        ck_abort_msg("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    ck_assert_msg(uid == userid,
                "Did not find the expected UID (found %llu expected %llu)",
                (unsigned long long) uid, (unsigned long long) userid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(fromname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Perform rename and check that GID is the same, but name changed */
    ret = sysdb_add_user(test_ctx->domain, toname, userid, 0,
                         fromname, "/", "/bin/sh", NULL, NULL, 0, 0);
    ck_assert_msg(ret == EEXIST, "A second user added with low level call?");

    ret = sysdb_store_user(test_ctx->domain, toname, NULL,
                           userid, 0, fromname, "/", "/bin/sh",
                           NULL, NULL, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "Could not add second user");

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, toname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the user from cache\n");
    if (res->count != 1) {
        ck_abort_msg("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    ck_assert_msg(uid == userid,
                "Did not find the expected UID (found %llu expected %llu)",
                (unsigned long long) uid, (unsigned long long) userid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(toname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Verify the first name is gone */
    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, fromname, &res);
    ck_assert_msg(ret == EOK, "Could not retrieve the user from cache\n");
    ck_assert_msg(res->count == 0, "Unexpectedly found the original user\n");

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_update_members)
{
    struct sysdb_test_ctx *test_ctx;
    char **add_groups;
    char **del_groups;
    const char *user = "testuser27000";
    char *user_fqname;
    const char *group_fqname;
    const char *check_fqname;
    errno_t ret;
    struct ldb_result *res;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    ck_assert_msg(ret == EOK, "Could not set up the test");

    user_fqname = sss_create_internal_fqname(test_ctx, user,
                                             test_ctx->domain->name);
    sss_ck_fail_if_msg(user_fqname == NULL, "user_fqname returned NULL");

    ret = sysdb_initgroups(test_ctx, test_ctx->domain, user_fqname, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed with error: %d", ret);
    ck_assert_int_eq(res->count, 1);   /* only the user itself */

    /* Add a user to two groups */
    add_groups = talloc_array(test_ctx, char *, 3);
    add_groups[0] = sss_create_internal_fqname(add_groups, "testgroup28001",
                                               test_ctx->domain->name);
    sss_ck_fail_if_msg(add_groups[0] == NULL, "Failed to create internal fqname for: %s",
                                   test_ctx->domain->name);
    add_groups[1] = sss_create_internal_fqname(add_groups, "testgroup28002",
                                               test_ctx->domain->name);
    sss_ck_fail_if_msg(add_groups[1] == NULL, "Failed to create internal fqname for: %s",
		                   test_ctx->domain->name);
    add_groups[2] = NULL;

    /* For later check */
    group_fqname = talloc_strdup(test_ctx, add_groups[1]);
    sss_ck_fail_if_msg(group_fqname == NULL, "Failed to allocate memory");

    ret = sysdb_update_members(test_ctx->domain, user_fqname,
                               SYSDB_MEMBER_USER,
                               (const char *const *)add_groups, NULL);
    ck_assert_msg(ret == EOK, "Could not add groups");

    ret = sysdb_initgroups(test_ctx, test_ctx->domain, user_fqname, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed with error: %d", ret);
    ck_assert_int_eq(res->count, 3);

    check_fqname = ldb_msg_find_attr_as_string(res->msgs[1], SYSDB_NAME, NULL);
    ck_assert_str_eq(check_fqname, add_groups[0]);
    check_fqname = ldb_msg_find_attr_as_string(res->msgs[2], SYSDB_NAME, NULL);
    ck_assert_str_eq(check_fqname, add_groups[1]);

    talloc_zfree(add_groups);

    /* Remove a user from one group and add to another */
    del_groups = talloc_array(test_ctx, char *, 2);
    del_groups[0] = sss_create_internal_fqname(del_groups, "testgroup28001",
                                               test_ctx->domain->name);
    del_groups[1] = NULL;
    add_groups = talloc_array(test_ctx, char *, 2);
    add_groups[0] = sss_create_internal_fqname(add_groups, "testgroup28003",
                                               test_ctx->domain->name);
    add_groups[1] = NULL;

    ret = sysdb_update_members(test_ctx->domain, user_fqname, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups,
                               (const char *const *)del_groups);
    ck_assert_msg(ret == EOK, "Group replace failed");

    ret = sysdb_initgroups(test_ctx, test_ctx->domain, user_fqname, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed with error: %d", ret);
    ck_assert_int_eq(res->count, 3);

    check_fqname = ldb_msg_find_attr_as_string(res->msgs[1], SYSDB_NAME, NULL);
    ck_assert_str_eq(check_fqname, group_fqname);
    check_fqname = ldb_msg_find_attr_as_string(res->msgs[2], SYSDB_NAME, NULL);
    ck_assert_str_eq(check_fqname, add_groups[0]);

    talloc_zfree(add_groups);
    talloc_zfree(del_groups);

    ret = sysdb_initgroups(test_ctx, test_ctx->domain, user_fqname, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed with error: %d", ret);
    ck_assert_int_eq(res->count, 3);

    /* Remove a user from two groups */
    del_groups = talloc_array(test_ctx, char *, 3);
    del_groups[0] = sss_create_internal_fqname(del_groups, "testgroup28002",
                                               test_ctx->domain->name);
    del_groups[1] = sss_create_internal_fqname(del_groups, "testgroup28003",
                                               test_ctx->domain->name);
    del_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->domain, user_fqname, SYSDB_MEMBER_USER,
                               NULL, (const char *const *)del_groups);
    ck_assert_msg(ret == EOK, "Could not remove groups");

    ret = sysdb_initgroups(test_ctx, test_ctx->domain, user_fqname, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_initgroups failed with error: %d", ret);
    ck_assert_int_eq(res->count, 1);   /* only the user itself */

    talloc_zfree(test_ctx);
}
END_TEST


START_TEST (test_sysdb_group_dn_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    struct ldb_dn *group_dn;
    char *parsed;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new_group(test_ctx, _i);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    group_dn = sysdb_group_dn(test_ctx, test_ctx->domain, data->groupname);
    sss_ck_fail_if_msg(group_dn == NULL, "OOM");

    ret = sysdb_group_dn_name(test_ctx->sysdb, test_ctx,
                              ldb_dn_get_linearized(group_dn), &parsed);
    sss_ck_fail_if_msg(ret != EOK, "Cannot get the group name from DN");

    sss_ck_fail_if_msg(strcmp(data->groupname, parsed) != 0,
            "Names don't match (got %s)", parsed);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_basic_netgroup)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_add_basic_netgroup(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not add netgroup %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_search_netgroup_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *netgrname;
    struct ldb_message *msg;
    struct ldb_dn *netgroup_dn;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_search_netgroup_by_name(test_ctx, test_ctx->domain,
                                        netgrname, NULL, &msg);
    sss_ck_fail_if_msg(ret != EOK, "Could not find netgroup with name %s", netgrname);

    netgroup_dn = sysdb_netgroup_dn(test_ctx, test_ctx->domain, netgrname);
    sss_ck_fail_if_msg(netgroup_dn == NULL, "Failed to allocate memory");
    sss_ck_fail_if_msg(ldb_dn_compare(msg->dn, netgroup_dn) != 0, "Found wrong netgroup!\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_netgroup_entry)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_entry(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove netgroup %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_netgroup_by_name)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_by_name(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not remove netgroup with name %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_set_netgroup_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_set_netgroup_attr(data);

    sss_ck_fail_if_msg(ret != EOK, "Could not set netgroup attribute %s", data->netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_netgroup_attr)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *description;
    const char *netgrname;
    struct ldb_result *res;
    const char *attrs[] = { SYSDB_DESCRIPTION, NULL };
    const char *attrval;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    description = talloc_asprintf(test_ctx, "Sysdb Netgroup %d", _i);
    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->domain, netgrname,
                                  attrs, &res);

    sss_ck_fail_if_msg(ret != EOK, "Could not get netgroup attributes");
    sss_ck_fail_if_msg(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_DESCRIPTION, 0);
    sss_ck_fail_if_msg(strcmp(attrval, description),
            "Got bad attribute value for netgroup %s", netgrname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_netgroup_base_dn)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_dn *base_dn;
    const char *strdn;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    base_dn = sysdb_netgroup_base_dn(test_ctx, test_ctx->domain);
    sss_ck_fail_if_msg(base_dn == NULL, "Could not get netgroup base DN");

    strdn = ldb_dn_get_linearized(base_dn);
    sss_ck_fail_if_msg(strdn == NULL, "Could not get string netgroup base DN");

    sss_ck_fail_if_msg(strstr(strdn, SYSDB_NETGROUP_CONTAINER) != strdn,
            "Malformed netgroup baseDN");
}
END_TEST

static errno_t netgr_triple_to_attrs(struct sysdb_attrs *attrs,
                                     struct sysdb_netgroup_ctx *netgrent)
{
    int ret;
    char *dummy;

    dummy = talloc_asprintf(attrs, "(%s,%s,%s)",
                            netgrent->value.triple.hostname,
                            netgrent->value.triple.username,
                            netgrent->value.triple.domainname);
    if (dummy == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_asprintf failed.\n");
        return ENOMEM;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_NETGROUP_TRIPLE, dummy);
    talloc_zfree(dummy);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sysdb_attrs_add_string failed.\n");
        return ret;
    }

    return EOK;
}

static errno_t store_netgr(struct sysdb_test_ctx *test_ctx,
                           const char *name,
                           struct sysdb_netgroup_ctx *netgrent)
{
    struct sysdb_attrs *attrs;
    errno_t ret;

    attrs = sysdb_new_attrs(test_ctx);
    if (attrs == NULL) {
        return ENOMEM;
    }

    ret = netgr_triple_to_attrs(attrs, netgrent);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_netgroup failed.\n");
        return ret;
    }

    ret = sysdb_add_netgroup(test_ctx->domain, name, NULL, attrs, NULL,
                             0, 0);
    talloc_zfree(attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_add_netgroup failed.\n");
        return ret;
    }

    return EOK;
}

static bool sysdb_netgr_ctx_cmp(struct sysdb_netgroup_ctx *a,
                                struct sysdb_netgroup_ctx *b)
{
    return a->type == b->type &&
           strcmp(a->value.triple.username, b->value.triple.username) == 0 &&
           strcmp(a->value.triple.hostname, b->value.triple.hostname) == 0 &&
           strcmp(a->value.triple.domainname, b->value.triple.domainname) == 0;
}

START_TEST (test_sysdb_netgr_to_entries)
{
    errno_t ret;
    bool bret;
    struct sysdb_test_ctx *test_ctx;
    struct sysdb_netgroup_ctx simple_netgroup = {
        .type = SYSDB_NETGROUP_TRIPLE_VAL,
        .value.triple.hostname = discard_const("host"),
        .value.triple.username = discard_const("user"),
        .value.triple.domainname = discard_const("domain"),
    };
    struct sysdb_netgroup_ctx ws_netgroup = {
        .type = SYSDB_NETGROUP_TRIPLE_VAL,
        .value.triple.hostname = discard_const(" host "),
        .value.triple.username = discard_const(" user "),
        .value.triple.domainname = discard_const(" domain "),
    };
    struct ldb_result *res;
    struct sysdb_netgroup_ctx **entries;
    size_t netgroup_count;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    ret = store_netgr(test_ctx, "simple_netgroup", &simple_netgroup);
    sss_ck_fail_if_msg(ret != EOK, "Could not store the netgr");

    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, "simple_netgroup", &res);
    ck_assert_msg(ret == EOK, "sysdb_getnetgr error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);
    ret = sysdb_netgr_to_entries(test_ctx, res, &entries, &netgroup_count);
    ck_assert_msg(ret == EOK, "sysdb_netgr_to_entries error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(netgroup_count == 1, "Received [%zd] triples", netgroup_count);
    bret = sysdb_netgr_ctx_cmp(entries[0], &simple_netgroup);
    ck_assert_msg(bret == true, "Netgroup triples do not match");

    ret = store_netgr(test_ctx, "ws_netgroup", &ws_netgroup);
    sss_ck_fail_if_msg(ret != EOK, "Could not store the netgr");

    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, "ws_netgroup", &res);
    ck_assert_msg(ret == EOK, "sysdb_getnetgr error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);
    ret = sysdb_netgr_to_entries(test_ctx, res, &entries, &netgroup_count);
    ck_assert_msg(ret == EOK, "sysdb_netgr_to_entries error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(netgroup_count == 1, "Received [%zd] triples", netgroup_count);
    bret = sysdb_netgr_ctx_cmp(entries[0], &simple_netgroup);
    ck_assert_msg(bret == true, "Netgroup triples do not match");
}
END_TEST

START_TEST(test_odd_characters)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct ldb_message *msg;
    const struct ldb_val *val;
    char *odd_username;
    const char odd_username_orig_dn[] =
        "\\2a\\28odd\\29\\5cuser,name,cn=users,dc=example,dc=com";
    char *odd_groupname;
    const char odd_netgroupname[] = "*(odd\\*)\\netgroup,name";
    const char *received_user;
    const char *received_group;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    static const char *netgr_attrs[] = SYSDB_NETGR_ATTRS;
    struct sysdb_netgroup_ctx **entries;
    size_t netgroup_count;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    odd_groupname = sss_create_internal_fqname(test_ctx,
                                               "*(odd\\*)\\group,name",
                                               test_ctx->domain->name);
    odd_username = sss_create_internal_fqname(test_ctx, "*(odd)\\user,name",
                                              test_ctx->domain->name);
    sss_ck_fail_if_msg(odd_groupname == NULL, "sss_create_internal_fqname failed");
    sss_ck_fail_if_msg(odd_username == NULL, "sss_create_internal_fqname failed");

    /* ===== Groups ===== */

    /* Add */
    ret = sysdb_add_incomplete_group(test_ctx->domain, odd_groupname,
                                     20000, NULL, NULL, NULL, true, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     odd_groupname, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_group_by_name error [%d][%s]",
                            ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, odd_groupname, &res);
    ck_assert_msg(ret == EOK, "sysdb_getgrnam error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_group = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(received_group, odd_groupname) == 0,
                "Expected [%s], got [%s]",
                odd_groupname, received_group);
    talloc_free(res);


    /* ===== Users ===== */

    /* Add */
    ret = sysdb_add_basic_user(test_ctx->domain,
                               odd_username,
                               10000, 10000,
                               "","","");
    ck_assert_msg(ret == EOK, "sysdb_add_basic_user error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_user_by_name(test_ctx,
                                    test_ctx->domain,
                                    odd_username, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_name error [%d][%s]",
                            ret, strerror(ret));
    val = ldb_dn_get_component_val(msg->dn, 0);
    ck_assert_msg(strcmp((char *)val->data, odd_username)==0,
                "Expected [%s] got [%s]\n",
                odd_username, (char *)val->data);
    talloc_zfree(msg);

    /* Add to the group */
    ret = sysdb_add_group_member(test_ctx->domain,
                                 odd_groupname, odd_username,
                                 SYSDB_MEMBER_USER, false);
    ck_assert_msg(ret == EOK, "sysdb_add_group_member error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, odd_username, &res);
    ck_assert_msg(ret == EOK, "sysdb_getpwnam error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_user = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    ck_assert_msg(strcmp(received_user, odd_username) == 0,
                "Expected [%s], got [%s]",
                odd_username, received_user);
    talloc_zfree(res);

    /* Attributes */
    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, odd_username,
                              user_attrs, &res);
    ck_assert_msg(ret == EOK, "sysdb_get_user_attr error [%d][%s]",
                            ret, strerror(ret));
    talloc_free(res);

    /* Delete User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    ck_assert_msg(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));

    /* Delete non existing User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    ck_assert_msg(ret == ENOENT, "sysdb_delete_user error [%d][%s]",
                               ret, strerror(ret));

    /* Delete Group */
    ret = sysdb_delete_group(test_ctx->domain, odd_groupname, 20000);
    ck_assert_msg(ret == EOK, "sysdb_delete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Add */
    ret = sysdb_add_user(test_ctx->domain,
                         odd_username,
                         10000, 0,
                         "","","",
                         odd_username_orig_dn,
                         NULL, 5400, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_user error [%d][%s]",
                            ret, strerror(ret));

    /* Delete User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    ck_assert_msg(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));

    /* ===== Netgroups ===== */
    /* Add */
    ret = sysdb_add_netgroup(test_ctx->domain,
                             odd_netgroupname, "No description",
                             NULL, NULL, 30, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_netgroup error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, odd_netgroupname, &res);
    ck_assert_msg(ret == EOK, "sysdb_getnetgr error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);
    talloc_zfree(res);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->domain,
                                  odd_netgroupname, netgr_attrs, &res);
    ck_assert_msg(ret == EOK, "sysdb_get_netgroup_attr error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);

    /* Parse */
    ret = sysdb_netgr_to_entries(test_ctx, res, &entries, &netgroup_count);
    ck_assert_msg(ret == EOK, "sysdb_netgr_to_entries error [%d][%s]",
                            ret, strerror(ret));

    talloc_zfree(res);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_SSS_LDB_SEARCH)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_dn *group_dn, *nonexist_dn;
    struct ldb_result *res;
    const char *groupname;
    const char *groupname_neg;
    const char *received_group;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    check_leaks_push(test_ctx);

    groupname = test_asprintf_fqname(test_ctx, test_ctx->domain,
                                     "test_group");
    sss_ck_fail_if_msg(groupname == NULL, "Failed to allocate memory");
    groupname_neg = test_asprintf_fqname(test_ctx, test_ctx->domain,
                                         "non_existing_test_group");
    sss_ck_fail_if_msg(groupname_neg == NULL, "Failed to allocate memory");

    group_dn = sysdb_group_dn(test_ctx, test_ctx->domain, groupname);
    sss_ck_fail_if_msg(group_dn == NULL, "sysdb_group_dn failed");

    nonexist_dn = sysdb_group_dn(test_ctx, test_ctx->domain,
                                 groupname_neg);
    sss_ck_fail_if_msg(nonexist_dn == NULL, "sysdb_group_dn failed");

    /* Add */
    ret = sysdb_add_incomplete_group(test_ctx->domain, groupname,
                                     20000, NULL, NULL, NULL, true, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                ret, strerror(ret));

    /* Retrieve */

    /* Empty filter */
    SSS_LDB_SEARCH(ret, test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                   LDB_SCOPE_BASE, NULL, NULL);

    ck_assert_msg(ret == EOK, "SSS_LDB_SEARCH error [%d][%s]",
                ret, strerror(ret));

    ck_assert_msg(res->count == 1, "Received [%d] responses",
                                 res->count);

    received_group = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME,
                                                 NULL);
    ck_assert_msg(strcmp(received_group, groupname) == 0,
                "Expected [%s], got [%s]", groupname, received_group);

    talloc_zfree(res);

    /* Non-empty filter */
    SSS_LDB_SEARCH(ret, test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                   LDB_SCOPE_BASE, NULL, SYSDB_GC);

    ck_assert_msg(ret == EOK, "SSS_LDB_SEARCH error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Filter yielding no results */
    SSS_LDB_SEARCH(ret, test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                   LDB_SCOPE_BASE, NULL,
                   "objectClass=nonExistingObjectClass");

    ck_assert_msg(ret == ENOENT, "sss_ldb_search error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Non-existing dn */
    SSS_LDB_SEARCH(ret, test_ctx->sysdb->ldb, test_ctx, &res, nonexist_dn,
                   LDB_SCOPE_BASE, NULL, NULL);

    ck_assert_msg(ret == ENOENT, "SSS_LDB_SEARCH error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    talloc_zfree(nonexist_dn);
    talloc_zfree(group_dn);
    talloc_zfree(groupname);
    talloc_zfree(groupname_neg);
    ck_assert_msg(check_leaks_pop(test_ctx) == true, "Memory leak");
}
END_TEST

/* == SERVICE TESTS == */
void services_check_match(struct sysdb_test_ctx *test_ctx,
                          bool by_name,
                          const char *primary_name,
                          int port,
                          const char **aliases,
                          const char **protocols)
{
    errno_t ret;
    unsigned int i, j;
    bool matched;
    const char *ret_name;
    int ret_port;
    struct ldb_result *res;
    struct ldb_message *msg;
    struct ldb_message_element *el;

    if (by_name) {
        /* Look up the service by name */
        ret = sysdb_getservbyname(test_ctx, test_ctx->domain, primary_name,
                                  NULL, &res);
        sss_ck_fail_if_msg(ret != EOK, "sysdb_getservbyname error [%s]\n",
                             strerror(ret));
    } else {
        /* Look up the newly-added service by port */
        ret = sysdb_getservbyport(test_ctx, test_ctx->domain, port, NULL,
                                  &res);
        sss_ck_fail_if_msg(ret != EOK, "sysdb_getservbyport error [%s]\n",
                             strerror(ret));
    }
    sss_ck_fail_if_msg(res == NULL, "ENOMEM");
    ck_assert_int_eq(res->count, 1);

    /* Make sure the returned entry matches */
    msg = res->msgs[0];
    ret_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    sss_ck_fail_if_msg(ret_name == NULL, "Cannot find attribute: " SYSDB_NAME);
    ck_assert_msg(strcmp(ret_name, primary_name) == 0,
                "Wrong value returned for attribute: %s. got: %s expected: %s",
                SYSDB_NAME, ret_name, primary_name);

    ret_port = ldb_msg_find_attr_as_int(msg, SYSDB_SVC_PORT, 0);
    ck_assert_int_eq(ret_port, port);

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; aliases[j]; j++) {
            if (strcmp(aliases[j], (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }
        sss_ck_fail_if_msg(!matched, "Unexpected value in LDB entry: [%s]",
                (const char *)el->values[i].data);
    }

    el = ldb_msg_find_element(msg, SYSDB_SVC_PROTO);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; protocols[j]; j++) {
            if (strcmp(protocols[j], (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }
        sss_ck_fail_if_msg(!matched, "Unexpected value in LDB entry: [%s]",
                (const char *)el->values[i].data);
    }
}

#define services_check_match_name(test_ctx, primary_name, port, aliases, protocols) \
    do { \
        services_check_match(test_ctx, true, primary_name, port, aliases, protocols); \
    } while(0);

#define services_check_match_port(test_ctx, primary_name, port, aliases, protocols) \
    do { \
        services_check_match(test_ctx, false, primary_name, port, aliases, protocols); \
    } while(0);

START_TEST(test_sysdb_add_services)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    char *primary_name;
    const char **aliases;
    const char **protocols;
    int port = 3890;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    primary_name = talloc_asprintf(test_ctx, "test_service");
    sss_ck_fail_if_msg(primary_name == NULL, "Failed to allocate memory");

    aliases = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(aliases == NULL, "Failed to allocate memory");

    aliases[0] = talloc_asprintf(aliases, "test_service_alias1");
    sss_ck_fail_if_msg(aliases[0] == NULL, "Failed to allocate memory");

    aliases[1] = talloc_asprintf(aliases, "test_service_alias2");
    sss_ck_fail_if_msg(aliases[1] == NULL, "Failed to allocate memory");

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(protocols == NULL, "Failed to allocate memory");

    protocols[0] = talloc_asprintf(protocols, "tcp");
    sss_ck_fail_if_msg(protocols[0] == NULL, "Failed to allocate memory");

    protocols[1] = talloc_asprintf(protocols, "udp");
    sss_ck_fail_if_msg(protocols[1] == NULL, "Failed to allocate memory");

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_svc_add(NULL, test_ctx->domain,
                        primary_name, port,
                        aliases, protocols,
                        NULL);
    ck_assert_msg(ret == EOK, "sysdb_svc_add error [%s]\n", strerror(ret));

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by name)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_svc_delete(test_ctx->domain, primary_name, 0, NULL);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_store_services)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *primary_name = "test_store_service";
    const char *alt_primary_name = "alt_test_store_service";
    const char **aliases;
    const char **protocols;
    int port = 3890;
    int altport = 3891;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    aliases = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(aliases == NULL, "Failed to allocate memory");

    aliases[0] = talloc_asprintf(aliases, "test_service_alias1");
    sss_ck_fail_if_msg(aliases[0] == NULL, "Failed to allocate memory");

    aliases[1] = talloc_asprintf(aliases, "test_service_alias2");
    sss_ck_fail_if_msg(aliases[1] == NULL, "Failed to allocate memory");

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(protocols == NULL, "Failed to allocate memory");

    protocols[0] = talloc_asprintf(protocols, "tcp");
    sss_ck_fail_if_msg(protocols[0] == NULL, "Failed to allocate memory");

    protocols[1] = talloc_asprintf(protocols, "udp");
    sss_ck_fail_if_msg(protocols[1] == NULL, "Failed to allocate memory");

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Store this group (which will add it) */
    ret = sysdb_store_service(test_ctx->domain,
                              primary_name, port,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Change the service name */
    ret = sysdb_store_service(test_ctx->domain,
                              alt_primary_name, port,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    services_check_match_name(test_ctx,
                              alt_primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              alt_primary_name, port,
                              aliases, protocols);


    /* Change it back */
    ret = sysdb_store_service(test_ctx->domain,
                              primary_name, port,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Change the port number */
    ret = sysdb_store_service(test_ctx->domain,
                              primary_name, altport,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, altport,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, altport,
                              aliases, protocols);

    /* TODO: Test changing aliases and protocols */

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by port)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_svc_delete(test_ctx->domain, NULL, altport, NULL);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

errno_t
sysdb_svc_remove_alias(struct sysdb_ctx *sysdb,
                       struct ldb_dn *dn,
                       const char *alias);

START_TEST(test_sysdb_svc_remove_alias)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *primary_name = "remove_alias_test";
    const char **aliases;
    const char **protocols;
    int port = 3990;
    struct ldb_dn *dn;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    aliases = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(aliases == NULL, "Failed to allocate memory");

    aliases[0] = talloc_asprintf(aliases, "remove_alias_alias1");
    sss_ck_fail_if_msg(aliases[0] == NULL, "Failed to allocate memory");

    aliases[1] = talloc_asprintf(aliases, "remove_alias_alias2");
    sss_ck_fail_if_msg(aliases[1] == NULL, "Failed to allocate memory");

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(protocols == NULL, "Failed to allocate memory");

    protocols[0] = talloc_asprintf(protocols, "tcp");
    sss_ck_fail_if_msg(protocols[0] == NULL, "Failed to allocate memory");

    protocols[1] = talloc_asprintf(protocols, "udp");
    sss_ck_fail_if_msg(protocols[1] == NULL, "Failed to allocate memory");

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_svc_add(NULL, test_ctx->domain,
                        primary_name, port,
                        aliases, protocols,
                        NULL);
    ck_assert_msg(ret == EOK, "sysdb_svc_add error [%s]\n", strerror(ret));

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Now remove an alias */
    dn = sysdb_svc_dn(test_ctx->sysdb, test_ctx, test_ctx->domain->name, primary_name);
    sss_ck_fail_if_msg(dn == NULL, "Failed to allocate memory");

    ret = sysdb_svc_remove_alias(test_ctx->sysdb, dn, aliases[1]);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_transaction_commit failed with error: %d", ret);

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_transaction_start failed with error: %d", ret);

    /* Set aliases[1] to NULL to perform validation checks */
    aliases[1] = NULL;

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

#define LC_NAME_ALIAS_TEST_VAL "TeSt VaLuE"
#define LC_NAME_ALIAS_CHECK_VAL "test value"
START_TEST(test_sysdb_attrs_add_lc_name_alias)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char *str;
    const char **list = NULL;

    ret = sysdb_attrs_add_lc_name_alias(NULL, NULL);
    ck_assert_msg(ret == EINVAL, "EINVAL not returned for NULL input");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_lc_name_alias(attrs, LC_NAME_ALIAS_TEST_VAL);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string(attrs, SYSDB_NAME_ALIAS, &str);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string failed");
    ck_assert_msg(strcmp(str, LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, str);

    /* Add the same value a second time, it is not recommended to do this on
     * purpose but the test should illustrate the different to
     * sysdb_attrs_add_lc_name_alias_safe(). */
    ret = sysdb_attrs_add_lc_name_alias(attrs, LC_NAME_ALIAS_TEST_VAL);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string_array(attrs, SYSDB_NAME_ALIAS, attrs, &list);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed");
    ck_assert_msg(list != NULL, "No list returned");
    ck_assert_msg(list[0] != NULL, "Missing first list element");
    ck_assert_msg(strcmp(list[0], LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, list[0]);
    ck_assert_msg(list[1] != NULL, "Missing second list element");
    ck_assert_msg(strcmp(list[1], LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, list[1]);
    ck_assert_msg(list[2] == NULL, "Missing list terminator");

    talloc_free(attrs);
}
END_TEST

START_TEST(test_sysdb_attrs_add_lc_name_alias_safe)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char *str;
    const char **list = NULL;

    ret = sysdb_attrs_add_lc_name_alias_safe(NULL, NULL);
    ck_assert_msg(ret == EINVAL, "EINVAL not returned for NULL input");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_lc_name_alias_safe(attrs, LC_NAME_ALIAS_TEST_VAL);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string(attrs, SYSDB_NAME_ALIAS, &str);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string failed");
    ck_assert_msg(strcmp(str, LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, str);

    /* Adding the same value a second time should be ignored */
    ret = sysdb_attrs_add_lc_name_alias_safe(attrs, LC_NAME_ALIAS_TEST_VAL);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string_array(attrs, SYSDB_NAME_ALIAS, attrs, &list);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed");
    ck_assert_msg(list != NULL, "No list returned");
    ck_assert_msg(list[0] != NULL, "Missing first list element");
    ck_assert_msg(strcmp(list[0], LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, list[0]);
    ck_assert_msg(list[1] == NULL, "Missing list terminator");

    /* Adding different value */
    ret = sysdb_attrs_add_lc_name_alias_safe(attrs,
                                             "2nd_" LC_NAME_ALIAS_TEST_VAL);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string_array(attrs, SYSDB_NAME_ALIAS, attrs, &list);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed");
    ck_assert_msg(list != NULL, "No list returned");
    ck_assert_msg(list[0] != NULL, "Missing first list element");
    ck_assert_msg(strcmp(list[0], LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, list[0]);
    ck_assert_msg(list[1] != NULL, "Missing first list element");
    ck_assert_msg(strcmp(list[1], "2nd_" LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                "2nd_" LC_NAME_ALIAS_CHECK_VAL, list[1]);
    ck_assert_msg(list[2] == NULL, "Missing list terminator");

    talloc_free(attrs);
}
END_TEST

START_TEST(test_sysdb_attrs_get_string_array)
{
    int ret;
    struct sysdb_attrs *attrs;
    const char **list;
    const char *attrname = "test_attr";
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *el = NULL;

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, attrname, "val1");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed");
    ret = sysdb_attrs_add_string(attrs, attrname, "val2");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_get_el_ext(attrs, attrname, false, &el);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_el_ext failed");

    list = sss_ldb_el_to_string_list(tmp_ctx, el);
    sss_ck_fail_if_msg(list == NULL, "sss_ldb_el_to_string_list failed");

    ck_assert_str_eq(list[0], "val1");
    ck_assert_str_eq(list[1], "val2");
    ck_assert_msg(list[2] == NULL, "Expected terminated list");

    talloc_free(list);

    ret = sysdb_attrs_get_string_array(attrs, attrname, tmp_ctx, &list);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed");

    /* This test relies on values keeping the same order. It is the case
     * with LDB, but if we ever switch from LDB, we need to amend the test
     */
    ck_assert_str_eq(list[0], "val1");
    ck_assert_str_eq(list[1], "val2");
    ck_assert_msg(list[2] == NULL, "Expected terminated list");

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_sysdb_attrs_add_val)
{
    int ret;
    struct sysdb_attrs *attrs;
    TALLOC_CTX *tmp_ctx;
    struct ldb_val val = {discard_const(TEST_ATTR_VALUE),
                          sizeof(TEST_ATTR_VALUE) - 1};

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_val(attrs, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_add_val(attrs, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ck_assert_msg(attrs->num == 1, "Unexpected number of attributes.");
    ck_assert_msg(strcmp(attrs->a[0].name, TEST_ATTR_NAME) == 0,
                "Unexpected attribute name.");
    ck_assert_msg(attrs->a[0].num_values == 2,
                "Unexpected number of attribute values.");
    ck_assert_msg(ldb_val_string_cmp(&attrs->a[0].values[0],
                                   TEST_ATTR_VALUE) == 0,
                "Unexpected attribute value.");
    ck_assert_msg(ldb_val_string_cmp(&attrs->a[0].values[1],
                                   TEST_ATTR_VALUE) == 0,
                "Unexpected attribute value.");

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_sysdb_attrs_add_val_safe)
{
    int ret;
    struct sysdb_attrs *attrs;
    TALLOC_CTX *tmp_ctx;
    struct ldb_val val = {discard_const(TEST_ATTR_VALUE),
                          sizeof(TEST_ATTR_VALUE) - 1};

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_val(attrs, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_add_val_safe(attrs, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ck_assert_msg(attrs->num == 1, "Unexpected number of attributes.");
    ck_assert_msg(strcmp(attrs->a[0].name, TEST_ATTR_NAME) == 0,
                "Unexpected attribute name.");
    ck_assert_msg(attrs->a[0].num_values == 1,
                "Unexpected number of attribute values.");
    ck_assert_msg(ldb_val_string_cmp(&attrs->a[0].values[0],
                                   TEST_ATTR_VALUE) == 0,
                "Unexpected attribute value.");

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_sysdb_attrs_add_string_safe)
{
    int ret;
    struct sysdb_attrs *attrs;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    attrs = sysdb_new_attrs(NULL);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, TEST_ATTR_NAME, TEST_ATTR_VALUE);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_add_string_safe(attrs, TEST_ATTR_NAME, TEST_ATTR_VALUE);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ck_assert_msg(attrs->num == 1, "Unexpected number of attributes.");
    ck_assert_msg(strcmp(attrs->a[0].name, TEST_ATTR_NAME) == 0,
                "Unexpected attribute name.");
    ck_assert_msg(attrs->a[0].num_values == 1,
                "Unexpected number of attribute values.");
    ck_assert_msg(ldb_val_string_cmp(&attrs->a[0].values[0],
                                   TEST_ATTR_VALUE) == 0,
                "Unexpected attribute value.");

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_sysdb_attrs_copy)
{
    int ret;
    struct sysdb_attrs *src;
    struct sysdb_attrs *dst;
    TALLOC_CTX *tmp_ctx;
    const char *val;
    const char **array;

    ret = sysdb_attrs_copy(NULL, NULL);
    ck_assert_msg(ret == EINVAL, "Wrong return code");

    tmp_ctx = talloc_new(NULL);
    ck_assert_msg(tmp_ctx != NULL, "talloc_new failed");

    src = sysdb_new_attrs(tmp_ctx);
    ck_assert_msg(src != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_copy(src, NULL);
    ck_assert_msg(ret == EINVAL, "Wrong return code");

    dst = sysdb_new_attrs(tmp_ctx);
    ck_assert_msg(dst != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_copy(NULL, dst);
    ck_assert_msg(ret == EINVAL, "Wrong return code");

    ret = sysdb_attrs_copy(src, dst);
    ck_assert_msg(ret == EOK, "sysdb_attrs_copy failed");
    ck_assert_msg(dst->num == 0, "Wrong number of elements");

    ret = sysdb_attrs_add_string(src, TEST_ATTR_NAME, TEST_ATTR_VALUE);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_copy(src, dst);
    ck_assert_msg(ret == EOK, "sysdb_attrs_copy failed");
    ck_assert_msg(dst->num == 1, "Wrong number of elements");
    ret = sysdb_attrs_get_string(dst, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string failed.\n");
    ck_assert_msg(strcmp(val, TEST_ATTR_VALUE) == 0, "Wrong attribute value.");

    /* Make sure the same entry is not copied twice */
    ret = sysdb_attrs_copy(src, dst);
    ck_assert_msg(ret == EOK, "sysdb_attrs_copy failed");
    ck_assert_msg(dst->num == 1, "Wrong number of elements");
    ret = sysdb_attrs_get_string(dst, TEST_ATTR_NAME, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string failed.\n");
    ck_assert_msg(strcmp(val, TEST_ATTR_VALUE) == 0, "Wrong attribute value.");

    /* Add new value to existing attribute */
    ret = sysdb_attrs_add_string(src, TEST_ATTR_NAME, TEST_ATTR_VALUE"_2nd");
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_copy(src, dst);
    ck_assert_msg(ret == EOK, "sysdb_attrs_copy failed");
    ck_assert_msg(dst->num == 1, "Wrong number of elements");
    ret = sysdb_attrs_get_string_array(dst, TEST_ATTR_NAME, tmp_ctx, &array);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed.\n");
    ck_assert_msg(strcmp(array[0], TEST_ATTR_VALUE) == 0,
                       "Wrong attribute value.");
    ck_assert_msg(strcmp(array[1], TEST_ATTR_VALUE"_2nd") == 0,
                       "Wrong attribute value.");
    ck_assert_msg(array[2] == NULL, "Wrong number of values.");

    /* Add new attribute */
    ret = sysdb_attrs_add_string(src, TEST_ATTR_NAME"_2nd", TEST_ATTR_VALUE);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed.");

    ret = sysdb_attrs_copy(src, dst);
    ck_assert_msg(ret == EOK, "sysdb_attrs_copy failed");
    ck_assert_msg(dst->num == 2, "Wrong number of elements");
    ret = sysdb_attrs_get_string_array(dst, TEST_ATTR_NAME, tmp_ctx, &array);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string_array failed.\n");
    ck_assert_msg(strcmp(array[0], TEST_ATTR_VALUE) == 0,
                       "Wrong attribute value.");
    ck_assert_msg(strcmp(array[1], TEST_ATTR_VALUE"_2nd") == 0,
                       "Wrong attribute value.");
    ck_assert_msg(array[2] == NULL, "Wrong number of values.");
    ret = sysdb_attrs_get_string(dst, TEST_ATTR_NAME"_2nd", &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_get_string failed.\n");
    ck_assert_msg(strcmp(val, TEST_ATTR_VALUE) == 0, "Wrong attribute value.");

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST (test_sysdb_search_return_ENOENT)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_dn *user_dn = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_message **msgs = NULL;
    struct ldb_result *res = NULL;
    size_t count;
    const char *str = NULL;
    struct test_data *data;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");
    check_leaks_push(test_ctx);

    /* id mapping */
    ret = sysdb_idmap_get_mappings(test_ctx, test_ctx->domain, &res);
    ck_assert_msg(ret == ENOENT, "sysdb_idmap_get_mappings error [%d][%s].",
                ret, strerror(ret));
    talloc_zfree(res);

    data = test_data_new_user(test_ctx, 1234);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->sid_str = "S-5-4-3-2-1";

    /* Search user */
    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain,
                                    data->username,
                                    NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_user_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_get_real_name(test_ctx, test_ctx->domain,
                              data->username, &str);
    ck_assert_msg(ret == ENOENT, "sysdb_get_real_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(str);

    ret = sysdb_search_user_by_uid(test_ctx, test_ctx->domain,
                                   data->uid, NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_user_by_uid error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_user_by_sid_str(test_ctx, test_ctx->domain,
                                       data->sid_str, NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_user_by_sid_str failed with "
                               "[%d][%s].", ret, strerror(ret));

    /* General search */
    user_dn = sysdb_user_dn(test_ctx, test_ctx->domain,
                            data->username);
    sss_ck_fail_if_msg(user_dn == NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(test_ctx, test_ctx->domain,
                           user_dn, NULL, "memberof", NULL,
                           &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_asq_search failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb,
                             user_dn, LDB_SCOPE_SUBTREE,
                             SYSDB_UC, NULL,
                             &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_entry failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);
    talloc_zfree(user_dn);

    /* SSS_LDB_SEARCH */
    user_dn = sysdb_user_dn(test_ctx, test_ctx->domain,
                            data->username);
    sss_ck_fail_if_msg(user_dn == NULL, "sysdb_user_dn failed");
    SSS_LDB_SEARCH(ret, test_ctx->sysdb->ldb, test_ctx, &res, user_dn,
                   LDB_SCOPE_BASE, NULL, SYSDB_UC);

    ck_assert_msg(ret == ENOENT, "SSS_LDB_SEARCH failed: %d, %s",
                               ret, strerror(ret));

    talloc_zfree(res);
    talloc_zfree(user_dn);

    /* Search group */
    talloc_zfree(data);
    data = test_data_new_group(test_ctx, 1234);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->sid_str = "S-5-4-3-2-1";

    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     data->groupname, NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_group_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_group_by_gid(test_ctx, test_ctx->domain,
                                    data->gid, NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_group_by_gid error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain,
                                        data->sid_str, NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_group_by_sid_str failed with "
                               "[%d][%s].", ret, strerror(ret));
    talloc_zfree(msg);
    talloc_zfree(data);

    /* Search netgroup */
    ret = sysdb_search_netgroup_by_name(test_ctx, test_ctx->domain,
                                        "nonexisting_netgroup", NULL, &msg);
    ck_assert_msg(ret == ENOENT, "sysdb_search_netgroup_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, "nonexisting_netgroup",
                         &res);
    ck_assert_msg(ret == ENOENT, "sysdb_getnetgr error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Search object */
    ret = sysdb_search_object_by_sid(test_ctx, test_ctx->domain,
                                     "S-5-4-3-2-1", NULL, &res);
    ck_assert_msg(ret == ENOENT, "sysdb_search_object_by_sid failed with "
                               "[%d][%s].", ret, strerror(ret));
    talloc_zfree(res);

    /* Search can return more results */
    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             "("SYSDB_SHELL"=/bin/nologin)", NULL,
                             &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_users failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_groups(test_ctx, test_ctx->domain,
                              "("SYSDB_GIDNUM"=1234)", NULL,
                              &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_groups failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_netgroups(test_ctx, test_ctx->domain,
                                 "("SYSDB_NAME"=nonexisting)", NULL,
                                 &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_netgroups failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    /* Search custom */
    ret = sysdb_search_custom(test_ctx, test_ctx->domain,
                              "(distinguishedName=nonexisting)",
                              CUSTOM_TEST_CONTAINER, NULL,
                              &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_custom failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_custom_by_name(test_ctx, test_ctx->domain,
                                     "nonexisting",
                                     CUSTOM_TEST_CONTAINER, NULL,
                                     &count, &msgs);
    ck_assert_msg(ret == ENOENT, "sysdb_search_custom_by_name failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    /* TODO: test sysdb_search_selinux_config */

    ck_assert_msg(check_leaks_pop(test_ctx) == true, "Memory leak");
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_has_enumerated)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    bool enumerated;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    ret = sysdb_has_enumerated(test_ctx->domain, SYSDB_HAS_ENUMERATED_ID,
                               &enumerated);
    sss_ck_fail_if_msg(ret != ENOENT,
            "Error [%d][%s] checking enumeration ENOENT is expected",
            ret, strerror(ret));

    ret = sysdb_set_enumerated(test_ctx->domain, SYSDB_HAS_ENUMERATED_ID,
                               true);
    sss_ck_fail_if_msg(ret != EOK, "Error [%d][%s] setting enumeration",
                        ret, strerror(ret));

    /* Recheck enumeration status */
    ret = sysdb_has_enumerated(test_ctx->domain, SYSDB_HAS_ENUMERATED_ID,
                               &enumerated);
    sss_ck_fail_if_msg(ret != EOK, "Error [%d][%s] checking enumeration",
                        ret, strerror(ret));

    ck_assert_msg(enumerated, "Enumeration should have been set to true");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_original_dn_case_insensitive)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    const char *filter;
    struct ldb_dn *base_dn;
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t num_msgs;
    char *c;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new(test_ctx);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->gid = 2900;

    data->groupname = test_asprintf_fqname(data, test_ctx->domain,
                                           "case_sensitive_group1");
    sss_ck_fail_if_msg(data->groupname == NULL, "Failed to allocate memory");

    data->orig_dn = talloc_asprintf(data, "cn=%s,cn=example,cn=com", data->groupname);
    sss_ck_fail_if_msg(data->orig_dn == NULL, "Failed to allocate memory");

    ret = test_add_incomplete_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* different name and GID, original DN differs only by case */
    data->gid = 2901;
    data->groupname = test_asprintf_fqname(data, test_ctx->domain,
                                           "case_sensitive_group2");
    sss_ck_fail_if_msg(data->groupname == NULL, "Failed to allocate memory");
    c = discard_const(data->orig_dn);
    while(*c != '\0') {
        *c = toupper(*c);
        c++;
    }

    ret = test_add_incomplete_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Search by originalDN should yield 2 entries */
    filter = talloc_asprintf(test_ctx, "%s=%s",
                             SYSDB_ORIG_DN, data->orig_dn);
    sss_ck_fail_if_msg(filter == NULL, "Cannot construct filter\n");

    base_dn = sysdb_domain_dn(test_ctx, test_ctx->domain);
    sss_ck_fail_if_msg(base_dn == NULL, "Cannot construct basedn\n");

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb,
                             base_dn, LDB_SCOPE_SUBTREE, filter, no_attrs,
                             &num_msgs, &msgs);
    ck_assert_msg(ret == EOK, "cache search error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(num_msgs == 2, "Did not find the expected number of entries using "
                               "case insensitive originalDN search");
}
END_TEST

START_TEST(test_sysdb_search_groups_by_orig_dn)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t num_msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_group(test_ctx, 456789);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->orig_dn = talloc_asprintf(data, "cn=%s,cn=example,cn=com", data->groupname);
    sss_ck_fail_if_msg(data->orig_dn == NULL, "Failed to allocate memory");

    ret = test_add_incomplete_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_search_groups_by_orig_dn(test_ctx, data->ctx->domain, data->orig_dn,
                                         no_attrs, &num_msgs, &msgs);
    ck_assert_msg(ret == EOK, "cache search error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(num_msgs == 1, "Did not find the expected number of entries using "
                               "sysdb_search_groups_by_orign_dn search");
}
END_TEST

START_TEST(test_sysdb_search_users_by_orig_dn)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t num_msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, 456789);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->orig_dn = talloc_asprintf(data, "cn=%s,cn=example,cn=com", data->username);
    sss_ck_fail_if_msg(data->orig_dn == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_ORIG_DN, data->orig_dn);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed with [%d][%s].",
                ret, strerror(ret));

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_search_users_by_orig_dn(test_ctx, data->ctx->domain, data->orig_dn,
                                        no_attrs, &num_msgs, &msgs);
    ck_assert_msg(ret == EOK, "cache search error [%d][%s]",
                            ret, strerror(ret));
    ck_assert_msg(num_msgs == 1, "Did not find the expected number of entries using "
                               "sysdb_search_users_by_orign_dn search");
}
END_TEST

START_TEST(test_sysdb_search_sid_str)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct ldb_message *msg;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_group(test_ctx, 2902);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->sid_str = "S-1-2-3-4";

    ret = test_add_incomplete_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain,
                                        data->sid_str, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_group_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    /* Delete the group by SID */
    ret = sysdb_delete_by_sid(test_ctx->sysdb, test_ctx->domain, data->sid_str);
    ck_assert_msg(ret == EOK, "sysdb_delete_by_sid failed with [%d][%s].",
                ret, strerror(ret));

    /* Verify it's gone */
    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain,
                                        data->sid_str, NULL, &msg);
    ck_assert_msg(ret == ENOENT,
                "sysdb_search_group_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    talloc_free(msg);
    msg = NULL;

    talloc_zfree(data);

    data = test_data_new_user(test_ctx, 12345);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->sid_str = "S-1-2-3-4-5";

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_SID_STR, data->sid_str);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed with [%d][%s].",
                ret, strerror(ret));

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_user_by_sid_str(test_ctx, test_ctx->domain,
                                       data->sid_str, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_search_object_by_id)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct test_data *data;
    const uint32_t id = 23456;
    uint32_t returned_id;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    /* test for missing entry */
    ret = sysdb_search_object_by_id(test_ctx, test_ctx->domain, 111, NULL,
                                    &res);
    ck_assert_msg(ret == ENOENT, "sysdb_search_object_by_name failed with "
                               "[%d][%s].", ret, strerror(ret));

    /* test user search */
    data = test_data_new_user(test_ctx, id);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_id(test_ctx, test_ctx->domain, id, NULL,
                                    &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_id failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_id = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    ck_assert_msg(id == returned_id,
                "Unexpected object found, expected UID [%"PRIu32"], "
                "got [%"PRIu32"].", id, returned_id);
    talloc_free(res);

    ret = test_remove_user(data);
    ck_assert_msg(ret == EOK,
                "test_remove_user failed with [%d][%s].", ret, strerror(ret));

    /* test group search */
    data = test_data_new_group(test_ctx, id);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_group failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_id(test_ctx, test_ctx->domain, id, NULL,
                                    &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_id failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_id = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    ck_assert_msg(id == returned_id,
                "Unexpected object found, expected GID [%"PRIu32"], "
                "got [%"PRIu32"].", id, returned_id);
    talloc_free(res);

    ret = test_remove_group(data);
    ck_assert_msg(ret == EOK,
                "test_remove_group failed with [%d][%s].", ret, strerror(ret));

    /* test for bad search filter bug #3283 */
    data = test_data_new_group(test_ctx, id);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = test_add_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_group failed with [%d][%s].",
                ret, strerror(ret));

    test_ctx->domain->mpg_mode = MPG_DISABLED;
    ret = sysdb_add_user(test_ctx->domain, "user1", 4001, id,
                         "User 1", "/home/user1", "/bin/bash",
                         NULL, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_add_user(test_ctx->domain, "user2", 4002, id,
                         "User 2", "/home/user2", "/bin/bash",
                         NULL, NULL, 0, 0);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_id(test_ctx, test_ctx->domain, id, NULL,
                                    &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_id failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_id = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    ck_assert_msg(id == returned_id,
                "Unexpected object found, expected GID [%"PRIu32"], "
                "got [%"PRIu32"].", id, returned_id);
    talloc_free(res);

    data->uid = 4001;
    ret = test_remove_user_by_uid(data);
    ck_assert_msg(ret == EOK,
                "test_remove_user_by_uid failed with error: %d", ret);

    data->uid = 4002;
    ret = test_remove_user_by_uid(data);
    ck_assert_msg(ret == EOK,
                "test_remove_user_by_uid failed with error: %d", ret);

    ret = test_remove_group(data);
    ck_assert_msg(ret == EOK, "test_remove_group failed with error: %d", ret);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_search_object_by_uuid)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *uuid;
    struct test_data *data;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, 123456);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    uuid = "11111111-2222-3333-4444-555555555555";

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_UUID, uuid);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed with [%d][%s].",
                ret, strerror(ret));

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_uuid(test_ctx, test_ctx->domain,
                                      "11111111-2222-3333-4444-555555555556",
                                      NULL, &res);
    ck_assert_msg(ret == ENOENT,
                "Unexpected return code from sysdb_search_object_by_uuid for "
                "missing object, expected [%d], got [%d].", ENOENT, ret);

    ret = sysdb_search_object_by_uuid(test_ctx, test_ctx->domain,
                                      uuid, NULL, &res);
    ck_assert_msg(ret == EOK, "sysdb_search_object_by_uuid failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, " \
                                 "expected [%u], get [%u].", 1, res->count);
    ck_assert_msg(strcmp(ldb_msg_find_attr_as_string(res->msgs[0],
                                                   SYSDB_NAME, ""),
                      data->username) == 0, "Unexpected object found, " \
                      "expected [%s], got [%s].", "UUIDuser",
                      ldb_msg_find_attr_as_string(res->msgs[0],SYSDB_NAME, ""));
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_search_object_by_name)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct test_data *data;
    const char *user_name = "John Doe";
    const char *group_name = "Domain Users";
    const char *lc_group_name = "domain users";
    const char *returned_name;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    /* test for missing entry */
    ret = sysdb_search_object_by_name(test_ctx, test_ctx->domain,
                                      "nonexisting_name", NULL, &res);
    ck_assert_msg(ret == ENOENT, "sysdb_search_object_by_name failed with "
                               "[%d][%s].", ret, strerror(ret));

    /* test user search */
    data = test_data_new_user(test_ctx, 23456);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->username = user_name;

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_name(test_ctx, test_ctx->domain,
                                      user_name, NULL, &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_name failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, ""),
    ck_assert_msg(strcmp(returned_name, data->username) == 0,
                "Unexpected object found, expected [%s], got [%s].",
                user_name, returned_name);
    talloc_free(res);

    ret = test_remove_user(data);
    ck_assert_msg(ret == EOK,
                "test_remove_user failed with [%d][%s].", ret, strerror(ret));

    /* test group search */
    data = test_data_new_group(test_ctx, 23456);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->groupname = group_name;

    ret = test_add_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_group failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_name(test_ctx, test_ctx->domain,
                                      group_name, NULL, &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_name failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, ""),
    ck_assert_msg(strcmp(returned_name, data->groupname) == 0,
                "Unexpected object found, expected [%s], got [%s].",
                group_name, returned_name);
    talloc_free(res);

    ret = test_remove_group(data);
    ck_assert_msg(ret == EOK,
                "test_remove_group failed with [%d][%s].", ret, strerror(ret));

    /* test case insensitive search */
    data = test_data_new_group(test_ctx, 23456);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->groupname = group_name;
    test_ctx->domain->case_sensitive = false;

    data->attrs = sysdb_new_attrs(test_ctx);
    sss_ck_fail_if_msg(data->attrs == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_lc_name_alias(data->attrs, group_name);
    ck_assert_msg(ret == EOK,
                "sysdb_attrs_add_lc_name_alias failed with error: %d", ret);

    ret = test_add_group(data);
    ck_assert_msg(ret == EOK, "sysdb_add_group failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_object_by_name(test_ctx, test_ctx->domain,
                                      lc_group_name, NULL, &res);
    ck_assert_msg(ret == EOK,
                "sysdb_search_object_by_name failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 1, res->count);

    returned_name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, ""),
    ck_assert_msg(strcmp(returned_name, data->groupname) == 0,
                "Unexpected object found, expected [%s], got [%s].",
                group_name, returned_name);

    talloc_free(res);

    talloc_free(test_ctx);
}
END_TEST

/* For simple searches the content of the certificate does not matter */
#define TEST_USER_CERT_DERB64 "gJznJT7L0aETU5CMk+n+1Q=="
START_TEST(test_sysdb_search_user_by_cert)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct ldb_val val;
    struct test_data *data;
    struct test_data *data2;
    const char *name;
    const char *name2;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    data = test_data_new_user(test_ctx, 234567);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    val.data = sss_base64_decode(test_ctx, TEST_USER_CERT_DERB64, &val.length);
    ck_assert_msg(val.data != NULL, "sss_base64_decode failed.");

    ret = sysdb_attrs_add_val(data->attrs, SYSDB_USER_MAPPED_CERT, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed with [%d][%s].",
                ret, strerror(ret));

    ret = test_add_user(data);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_user_by_cert(test_ctx, test_ctx->domain, "ABA=", &res);
    ck_assert_msg(ret == ENOENT,
                "Unexpected return code from sysdb_search_user_by_cert for "
                "missing object, expected [%d], got [%d].", ENOENT, ret);

    ret = sysdb_search_user_by_cert(test_ctx, test_ctx->domain,
                                    TEST_USER_CERT_DERB64, &res);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_cert failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 1, "Unexpected number of results, " \
                                 "expected [%u], get [%u].", 1, res->count);
    ck_assert_msg(strcmp(ldb_msg_find_attr_as_string(res->msgs[0],
                                                   SYSDB_NAME, ""),
                      data->username) == 0, "Unexpected object found, " \
                      "expected [%s], got [%s].", data->username,
                      ldb_msg_find_attr_as_string(res->msgs[0],SYSDB_NAME, ""));

    /* Add a second user with the same certificate */
    data2 = test_data_new_user(test_ctx, 2345671);
    sss_ck_fail_if_msg(data2 == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_val(data2->attrs, SYSDB_USER_MAPPED_CERT, &val);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_val failed with [%d][%s].",
                ret, strerror(ret));

    ret = test_add_user(data2);
    ck_assert_msg(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_user_by_cert(test_ctx, test_ctx->domain,
                                    TEST_USER_CERT_DERB64, &res);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_cert failed with [%d][%s].",
                ret, strerror(ret));
    ck_assert_msg(res->count == 2, "Unexpected number of results, "
                                 "expected [%u], get [%u].", 2, res->count);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, "");
    ck_assert_msg(name != NULL, "Failed to find attribute: " SYSDB_NAME);
    name2 = ldb_msg_find_attr_as_string(res->msgs[1], SYSDB_NAME, "");
    ck_assert_msg(name2 != NULL, "Failed to find attribute: " SYSDB_NAME);
    ck_assert_msg(((strcmp(name, data->username) == 0
                        && strcmp(name2, data2->username) == 0)
                    || (strcmp(name, data2->username) == 0
                        && strcmp(name2, data->username) == 0)),
                "Unexpected names found, expected [%s,%s], got [%s,%s].",
                data->username, data2->username, name, name2);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_delete_by_sid)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    check_leaks_push(test_ctx);

    /* Delete the group by SID */
    ret = sysdb_delete_by_sid(test_ctx->sysdb, test_ctx->domain,
                              "S-1-2-3-4-NON_EXISTING_SID");
    ck_assert_msg(ret == EOK, "sysdb_delete_by_sid failed with [%d][%s].",
                ret, strerror(ret));

    ck_assert_msg(check_leaks_pop(test_ctx) == true, "Memory leak");
    talloc_free(test_ctx);
}
END_TEST

const char *const testdom[4] = { "test.sub", "TEST.SUB", "test", "S-3" };

START_TEST(test_sysdb_subdomain_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct sss_domain_info *subdomain = NULL;
    struct ldb_result *results = NULL;
    struct ldb_dn *base_dn = NULL;
    struct ldb_dn *check_dn = NULL;
    const char *attrs[] = { SYSDB_NAME, SYSDB_NAME_ALIAS, NULL };
    struct ldb_message *msg;
    struct test_data *data;
    char *alias;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], MPG_DISABLED, false, NULL, NULL, 0, IPA_TRUST_UNKNOWN, NULL, true);
    ck_assert_msg(subdomain != NULL, "Failed to create new subdomain.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0], testdom[3],
                                false, false, NULL, 0, IPA_TRUST_UNKNOWN, NULL);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain, NULL);
    ck_assert_msg(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    data = test_data_new_user(test_ctx, 12345);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->username = test_asprintf_fqname(data, subdomain, "SubDomUser");

    alias = test_asprintf_fqname(data, subdomain, "subdomuser");
    sss_ck_fail_if_msg(alias == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_NAME_ALIAS, alias);
    ck_assert_msg(ret == EOK, "sysdb_store_user failed.");

    ret = sysdb_store_user(subdomain, data->username,
                           NULL, data->uid, 0, "Sub Domain User",
                           "/home/subdomuser", "/bin/bash",
                           NULL, data->attrs, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "sysdb_store_user failed.");

    base_dn =ldb_dn_new(test_ctx, test_ctx->sysdb->ldb, "cn=sysdb");
    ck_assert_msg(base_dn != NULL, "Failed to allocate memory");

    check_dn = sysdb_user_dn(data, subdomain, data->username);
    ck_assert_msg(check_dn != NULL, "Failed to allocate memory");

    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=%s", data->username);
    ck_assert_msg(ret == EOK, "ldb_search failed.");
    ck_assert_msg(results->count == 1, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     1, results->count);
    ck_assert_msg(ldb_dn_compare(results->msgs[0]->dn, check_dn) == 0,
                "Unexpected DN returned");

    /* Subdomains are case-insensitive. Test that the lowercased name
     * can be found, too */
    ret = sysdb_search_user_by_name(test_ctx, subdomain, alias,
                                    attrs, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_name failed.");

    ret = sysdb_delete_user(subdomain, alias, 0);
    ck_assert_msg(ret == EOK, "sysdb_delete_user failed [%d][%s].",
                            ret, strerror(ret));

    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=%s", alias);
    ck_assert_msg(ret == EOK, "ldb_search failed.");
    ck_assert_msg(results->count == 0, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     0, results->count);
}
END_TEST

START_TEST(test_sysdb_subdomain_content_delete)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct sss_domain_info *subdomain = NULL;
    struct ldb_result *results = NULL;
    struct ldb_dn *base_dn = NULL;
    struct ldb_dn *check_dn = NULL;
    struct ldb_dn *check_dom_dn = NULL;
    struct test_data *data;
    char *alias;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], MPG_DISABLED, false, NULL, NULL, 0, IPA_TRUST_UNKNOWN, NULL, true);
    ck_assert_msg(subdomain != NULL, "Failed to create new subdomain.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0], testdom[3],
                                false, false, NULL, 0, IPA_TRUST_UNKNOWN, NULL);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain, NULL);
    ck_assert_msg(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    data = test_data_new_user(test_ctx, 12345);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->username = test_asprintf_fqname(data, subdomain, "SubDomUser");

    alias = test_asprintf_fqname(data, subdomain, "subdomuser");
    sss_ck_fail_if_msg(alias == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_NAME_ALIAS, alias);
    ck_assert_msg(ret == EOK, "sysdb_store_user failed.");

    ret = sysdb_store_user(subdomain, data->username,
                           NULL, data->uid, 0, "Sub Domain User",
                           "/home/subdomuser", "/bin/bash",
                           NULL, data->attrs, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "sysdb_store_user failed.");

    base_dn =ldb_dn_new(test_ctx, test_ctx->sysdb->ldb, "cn=sysdb");
    ck_assert_msg(base_dn != NULL, "Failed to allocate memory");

    check_dn = sysdb_user_dn(data, subdomain, data->username);
    ck_assert_msg(check_dn != NULL, "Failed to allocate memory");

    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=%s", data->username);
    ck_assert_msg(ret == EOK, "ldb_search failed.");
    ck_assert_msg(results->count == 1, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     1, results->count);
    ck_assert_msg(ldb_dn_compare(results->msgs[0]->dn, check_dn) == 0,
                "Unexpected DN returned");

    ret = sysdb_subdomain_content_delete(test_ctx->sysdb, testdom[0]);
    ck_assert_msg(ret == EOK, "sysdb_subdomain_content_delete failed.");

    /* Check if user is removed */
    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=%s", alias);
    ck_assert_msg(ret == EOK, "ldb_search failed.");
    ck_assert_msg(results->count == 0, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     0, results->count);

    check_dom_dn = ldb_dn_new_fmt(test_ctx, test_ctx->sysdb->ldb,
                                  SYSDB_DOM_BASE, testdom[0]);
    ck_assert_msg(check_dom_dn != NULL, "ldb_dn_new_fmt failed.");

    /* Check if domain object is still present */
    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "cn=%s", testdom[0]);
    ck_assert_msg(ret == EOK, "ldb_search failed.");
    ck_assert_msg(results->count == 1, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     1, results->count);
    ck_assert_msg(ldb_dn_compare(results->msgs[0]->dn, check_dom_dn) == 0,
                "Unexpected DN returned");

}
END_TEST

START_TEST(test_sysdb_subdomain_user_ops)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct sss_domain_info *subdomain = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_dn *check_dn = NULL;
    struct test_data *data;
    const char *name;
    const char *shortname = "subdomuser";
    char *short_check;
    char *dom_check;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], MPG_DISABLED, false, NULL, NULL, 0, IPA_TRUST_UNKNOWN, NULL, true);
    ck_assert_msg(subdomain != NULL, "Failed to create new subdomain.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0], testdom[3],
                                false, false, NULL, 0, IPA_TRUST_UNKNOWN, NULL);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain, NULL);
    ck_assert_msg(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    data = test_data_new_user(test_ctx, 12345);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    data->username = test_asprintf_fqname(data, subdomain, shortname);
    sss_ck_fail_if_msg(data->username == NULL, "Failed to allocate memory");

    ret = sysdb_store_user(subdomain, data->username,
                           NULL, data->uid, 0, "Sub Domain User",
                           "/home/subdomuser", "/bin/bash",
                           NULL, NULL, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "sysdb_store_domuser failed.");

    check_dn = sysdb_user_dn(data, subdomain, data->username);
    ck_assert_msg(check_dn != NULL, "Failed to allocate memory");

    ret = sysdb_search_user_by_name(test_ctx, subdomain,
                                    data->username, NULL,
                                    &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_name failed with [%d][%s].",
                            ret, strerror(ret));
    ck_assert_msg(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpected DN returned");

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    sss_ck_fail_if_msg(name == NULL, "Failed to find attribute: " SYSDB_NAME);

    ret = sss_parse_internal_fqname(data, name, &short_check, &dom_check);
    sss_ck_fail_if_msg(ret != EOK, "sss_parse_internal_fqname failed with error: %d", ret);
    ck_assert_str_eq(short_check, shortname);
    ck_assert_str_eq(dom_check, subdomain->name);

    ret = sysdb_search_user_by_uid(test_ctx, subdomain, data->uid, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_domuser_by_uid failed with [%d][%s].",
                            ret, strerror(ret));
    ck_assert_msg(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpected DN returned");

    ret = sysdb_delete_user(subdomain, data->username, data->uid);
    ck_assert_msg(ret == EOK, "sysdb_delete_domuser failed with [%d][%s].",
                            ret, strerror(ret));
}
END_TEST

START_TEST(test_sysdb_subdomain_group_ops)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct sss_domain_info *subdomain = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_dn *check_dn = NULL;
    struct test_data *data;
    char *alias;
    const char *name;
    const char *shortname = "subDomGroup";
    char *short_check;
    char *dom_check;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[0],
                              testdom[3], MPG_DISABLED, false, NULL, NULL, 0, IPA_TRUST_UNKNOWN, NULL, true);
    ck_assert_msg(subdomain != NULL, "Failed to create new subdomain.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[0], testdom[3],
                                false, false, NULL, 0, IPA_TRUST_UNKNOWN, NULL);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain, NULL);
    ck_assert_msg(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    data = test_data_new_group(test_ctx, 12345);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");
    data->groupname = test_asprintf_fqname(data, subdomain, shortname);

    alias = test_asprintf_fqname(data, subdomain, "subdomgroup");
    sss_ck_fail_if_msg(alias == NULL, "Failed to allocate memory");

    ret = sysdb_attrs_add_string(data->attrs, SYSDB_NAME_ALIAS, alias);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_group(subdomain,
                            data->groupname, data->gid, data->attrs, -1, 0);
    ck_assert_msg(ret == EOK, "sysdb_store_group failed.");

    check_dn = sysdb_group_dn(data, subdomain, data->groupname);
    ck_assert_msg(check_dn != NULL, "Failed to allocate memory");

    ret = sysdb_search_group_by_name(test_ctx, subdomain, data->groupname, NULL,
                                     &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_group_by_name failed with [%d][%s].",
                            ret, strerror(ret));
    ck_assert_msg(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpected DN returned");

    /* subdomains are case insensitive, so it should be possible to search
    the group with a lowercase name version, too */
    /* Fixme - lowercase this */
    ret = sysdb_search_group_by_name(test_ctx, subdomain, data->groupname, NULL,
                                     &msg);
    ck_assert_msg(ret == EOK, "case-insensitive group search failed with [%d][%s].",
                            ret, strerror(ret));
    ck_assert_msg(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpected DN returned");

    name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    sss_ck_fail_if_msg(name == NULL, "Failed to find attribute: " SYSDB_NAME);

    ret = sss_parse_internal_fqname(data, name, &short_check, &dom_check);
    sss_ck_fail_if_msg(ret != EOK, "sss_parse_internal_fqname failed with error: %d", ret);
    ck_assert_str_eq(short_check, shortname);
    ck_assert_str_eq(dom_check, subdomain->name);

    ret = sysdb_search_group_by_gid(test_ctx, subdomain, data->gid, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_group_by_gid failed with [%d][%s].",
                            ret, strerror(ret));
    ck_assert_msg(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpected DN returned");

    ret = sysdb_delete_group(subdomain, data->groupname, data->gid);
    ck_assert_msg(ret == EOK, "sysdb_delete_group failed with [%d][%s].",
                            ret, strerror(ret));
}
END_TEST

#ifdef BUILD_AUTOFS
START_TEST(test_autofs_create_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    const char *origdn;
    errno_t ret;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    origdn = talloc_asprintf(test_ctx, "cn=testmap%d,dc=test", _i);
    sss_ck_fail_if_msg(origdn == NULL, "Out of memory\n");

    ret = sysdb_save_autofsmap(test_ctx->domain, autofsmapname,
                               autofsmapname, origdn, NULL, 0, 0, false);
    sss_ck_fail_if_msg(ret != EOK, "Could not store autofs map %s", autofsmapname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_retrieve_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;
    struct ldb_message *map = NULL;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_get_map_byname(test_ctx, test_ctx->domain,
                               autofsmapname, &map);
    sss_ck_fail_if_msg(ret != EOK, "Could not retrieve autofs map %s", autofsmapname);
    sss_ck_fail_if_msg(map == NULL, "No map retrieved?\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_delete_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_delete_autofsmap(test_ctx->domain, autofsmapname);
    sss_ck_fail_if_msg(ret != EOK, "Could not retrieve autofs map %s", autofsmapname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_retrieve_map_neg)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;
    struct ldb_message *map = NULL;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_get_map_byname(test_ctx, test_ctx->domain,
                               autofsmapname, &map);
    sss_ck_fail_if_msg(ret != ENOENT, "Expected ENOENT, got %d instead\n", ret);
    sss_ck_fail_if_msg(map != NULL, "Unexpected map found\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_store_entry_in_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    const char *autofskey;
    const char *autofsval;
    errno_t ret;
    int ii;
    const int limit = 10;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    for (ii=0; ii < limit; ii++) {
        autofskey = talloc_asprintf(test_ctx, "%s_testkey%d",
                                    autofsmapname, ii);
        sss_ck_fail_if_msg(autofskey == NULL, "Out of memory\n");

        autofsval = talloc_asprintf(test_ctx, "testserver:/testval%d", ii);
        sss_ck_fail_if_msg(autofsval == NULL, "Out of memory\n");

        ret = sysdb_save_autofsentry(test_ctx->domain,
                                     autofsmapname, autofskey,
                                     autofsval, NULL, 0, 0);
        sss_ck_fail_if_msg(ret != EOK, "Could not save autofs entry %s", autofskey);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_retrieve_keys_by_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;
    size_t count;
    struct ldb_message **entries;
    const int expected = 10;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_autofs_entries_by_map(test_ctx, test_ctx->domain,
                                      autofsmapname, &count, &entries);
    sss_ck_fail_if_msg(ret != EOK, "Cannot get autofs entries for map %s\n",
            autofsmapname);
    sss_ck_fail_if_msg(count != expected, "Expected to find %d entries, got %zd\n",
            expected, count);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_key_duplicate)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    const char *autofskey;
    const char *autofsval;
    errno_t ret;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    sss_ck_fail_if_msg(autofsmapname == NULL, "Out of memory\n");

    autofskey = talloc_asprintf(test_ctx, "testkey");
    sss_ck_fail_if_msg(autofskey == NULL, "Out of memory\n");

    autofsval = talloc_asprintf(test_ctx, "testserver:/testval%d", _i);
    sss_ck_fail_if_msg(autofsval == NULL, "Out of memory\n");

    ret = sysdb_save_autofsentry(test_ctx->domain,
                                 autofsmapname, autofskey,
                                 autofsval, NULL, 0, 0);
    sss_ck_fail_if_msg(ret != EOK, "Could not save autofs entry %s", autofskey);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_get_duplicate_keys)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofskey;
    errno_t ret;
    const char *attrs[] = { SYSDB_AUTOFS_ENTRY_KEY,
                            SYSDB_AUTOFS_ENTRY_VALUE,
                            NULL };
    size_t count;
    struct ldb_message **msgs;
    struct ldb_dn *dn;
    const char *filter;
    const int expected = 10;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    autofskey = talloc_asprintf(test_ctx, "testkey");
    sss_ck_fail_if_msg(autofskey == NULL, "Out of memory\n");

    filter = talloc_asprintf(test_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_ENTRY_OC, SYSDB_AUTOFS_ENTRY_KEY, autofskey);
    sss_ck_fail_if_msg(filter == NULL, "Out of memory\n");

    dn = ldb_dn_new_fmt(test_ctx, test_ctx->sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        AUTOFS_MAP_SUBDIR, test_ctx->domain->name);
    sss_ck_fail_if_msg(dn == NULL, "Out of memory\n");

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb, dn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    ck_assert_msg(ret == EOK, "sysdb_search_entry returned [%d]", ret);
    sss_ck_fail_if_msg(count != expected, "Found %zd entries with name %s, expected %d\n",
            count, autofskey, expected);
    talloc_free(test_ctx);
}
END_TEST

#endif /* BUILD_AUTOFS */

static struct confdb_ctx *test_cdb_domains_prep(TALLOC_CTX *mem_ctx)
{
    char *conf_db;
    int ret;
    struct confdb_ctx *confdb;

    /* Create tests directory if it doesn't exist */
    /* (relative to current dir) */
    ret = mkdir(TESTS_PATH, 0775);
    if (ret == -1 && errno != EEXIST) {
        ck_abort_msg("Could not create %s directory", TESTS_PATH);
        return NULL;
    }

    conf_db = talloc_asprintf(mem_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    ck_assert(conf_db != NULL);

    /* Make sure the test domain does not interfere with our testing */
    ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
    if (ret != EOK && errno != ENOENT) {
        ck_abort_msg("Could not remove confdb %s\n", TESTS_PATH"/"TEST_CONF_FILE);
        return NULL;
    }

    /* Connect to the conf db */
    ret = confdb_init(mem_ctx, &confdb, conf_db);
    ck_assert_int_eq(ret, EOK);

    return confdb;
}

START_TEST(test_confdb_list_all_domain_names_no_dom)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *confdb;
    char **names;

    tmp_ctx = talloc_new(NULL);
    ck_assert(tmp_ctx != NULL);

    confdb = test_cdb_domains_prep(tmp_ctx);
    ck_assert(confdb != NULL);

    /* No domain */
    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    ck_assert_int_eq(ret, EOK);
    ck_assert(names != NULL);
    ck_assert(names[0] == NULL);

    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_confdb_list_all_domain_names_single_dom)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *confdb;
    char **names;

    const char *val[2];
    val[1] = NULL;

    tmp_ctx = talloc_new(NULL);
    ck_assert(tmp_ctx != NULL);

    confdb = test_cdb_domains_prep(tmp_ctx);
    ck_assert(confdb != NULL);

    /* One domain */
    val[0] = "FILES";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "proxy";
    ret = confdb_add_param(confdb, true,
                           "config/domain/FILES", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    ck_assert_int_eq(ret, EOK);
    ck_assert(names != NULL);
    ck_assert_str_eq(names[0], "FILES");
    ck_assert(names[1] == NULL);

    talloc_free(tmp_ctx);
}
END_TEST

#define UPN_USER_NAME "upn_user"
#define UPN_PRINC "upn_user@UPN.TEST"
#define UPN_PRINC_WRONG_CASE "UpN_uSeR@uPn.TeSt"
#define UPN_CANON_PRINC "upn_user@UPN.CANON"
#define UPN_CANON_PRINC_WRONG_CASE "uPn_UsEr@UpN.CaNoN"

START_TEST(test_upn_basic)
{
    struct sysdb_test_ctx *test_ctx;
    struct sysdb_attrs *attrs;
    int ret;
    struct ldb_message *msg;
    const char *str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    attrs = sysdb_new_attrs(test_ctx);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed.\n");

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, UPN_PRINC);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_attrs_add_string(attrs, SYSDB_CANONICAL_UPN, UPN_CANON_PRINC);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_user(test_ctx->domain,
                           UPN_USER_NAME, "x",
                           12345, 0, "UPN USER", "/home/upn_user",
                           "/bin/bash", NULL,
                           attrs, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "Could not store user.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   "abc@def.ghi", NULL, &msg);
    ck_assert_msg(ret == ENOENT,
                "sysdb_search_user_by_upn failed with non-existing UPN.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_PRINC, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    /* check if input is sanitized */
    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   "abc@def.ghi)(name="UPN_USER_NAME")(abc=xyz",
                                   NULL, &msg);
    ck_assert_msg(ret == ENOENT,
                "sysdb_search_user_by_upn failed with un-sanitized input.");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_upn_basic_case)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_message *msg;
    const char *str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_PRINC_WRONG_CASE, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_upn_canon)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_message *msg;
    const char *str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_CANON_PRINC, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_CANON_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_CANON_PRINC, str);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_upn_canon_case)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_message *msg;
    const char *str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_CANON_PRINC_WRONG_CASE, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_CANON_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_CANON_PRINC, str);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_upn_dup)
{
    struct sysdb_test_ctx *test_ctx;
    struct sysdb_attrs *attrs;
    int ret;
    struct ldb_message *msg;
    const char *str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        ck_abort_msg("Could not set up the test");
        return;
    }

    attrs = sysdb_new_attrs(test_ctx);
    ck_assert_msg(attrs != NULL, "sysdb_new_attrs failed.\n");

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, UPN_CANON_PRINC);
    ck_assert_msg(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_user(test_ctx->domain,
                           UPN_USER_NAME"_dup", "x",
                           23456, 0, "UPN USER DUP", "/home/upn_user_dup",
                           "/bin/bash", NULL,
                           attrs, NULL, -1, 0);
    ck_assert_msg(ret == EOK, "Could not store user.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_CANON_PRINC, NULL, &msg);
    ck_assert_msg(ret == EINVAL,
                "sysdb_search_user_by_upn failed for duplicated UPN.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain, false,
                                   UPN_PRINC, NULL, &msg);
    ck_assert_msg(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    ck_assert_msg(str != NULL, "ldb_msg_find_attr_as_string failed.");
    ck_assert_msg(strcmp(str, UPN_CANON_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_CANON_PRINC, str);

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_gpo_store_retrieve)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct ldb_result *result = NULL;
    const char *guid;
    int version;
    static const char *test_guid = "3610EDA5-77EF-11D2-8DC5-00C04FA31A66";

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    ret = sysdb_gpo_get_gpo_by_guid(test_ctx, test_ctx->domain,
                                    test_guid,
                                    &result);
    sss_ck_fail_if_msg(ret != ENOENT, "GPO present in cache before store op");

    ret = sysdb_gpo_get_gpos(test_ctx, test_ctx->domain, &result);
    sss_ck_fail_if_msg(ret != ENOENT, "GPO present in cache before store op");

    ret = sysdb_gpo_store_gpo(test_ctx->domain,
                              test_guid, 1, 5, 0);
    sss_ck_fail_if_msg(ret != EOK, "Could not store a test GPO");

    ret = sysdb_gpo_get_gpos(test_ctx, test_ctx->domain, &result);
    sss_ck_fail_if_msg(ret != EOK, "GPOs not in cache after store op");
    sss_ck_fail_if_msg(result == NULL, "Could not get GPOs");
    ck_assert_int_eq(result->count, 1);

    result = NULL;
    ret = sysdb_gpo_get_gpo_by_guid(test_ctx, test_ctx->domain,
                                    test_guid, &result);
    sss_ck_fail_if_msg(ret != EOK, "GPO not in cache after store op");
    sss_ck_fail_if_msg(result == NULL, "Could not get GPOs by guid: %s", test_guid);
    ck_assert_int_eq(result->count, 1);

    guid = ldb_msg_find_attr_as_string(result->msgs[0],
                                       SYSDB_GPO_GUID_ATTR, NULL);
    ck_assert_str_eq(guid, test_guid);

    version = ldb_msg_find_attr_as_uint(result->msgs[0],
                                        SYSDB_GPO_VERSION_ATTR, 0);
    ck_assert_int_eq(version, 1);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_gpo_replace)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct ldb_result *result = NULL;
    const char *guid;
    int version;
    static const char *test_guid = "3610EDA5-77EF-11D2-8DC5-00C04FA31A66";

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not setup the test");

    ret = sysdb_gpo_get_gpo_by_guid(test_ctx, test_ctx->domain,
                                    test_guid, &result);
    sss_ck_fail_if_msg(ret != EOK, "GPO not in cache after store op");
    sss_ck_fail_if_msg(result == NULL, "Could not get GPOs by guid: %s", test_guid);
    ck_assert_int_eq(result->count, 1);

    guid = ldb_msg_find_attr_as_string(result->msgs[0],
                                       SYSDB_GPO_GUID_ATTR, NULL);
    ck_assert_str_eq(guid, test_guid);

    version = ldb_msg_find_attr_as_uint(result->msgs[0],
                                        SYSDB_GPO_VERSION_ATTR, 0);
    ck_assert_int_eq(version, 1);

    /* Modify the version */
    ret = sysdb_gpo_store_gpo(test_ctx->domain,
                              test_guid, 2, 5, 0);
    sss_ck_fail_if_msg(ret != EOK, "Could not store a test GPO");

    ret = sysdb_gpo_get_gpo_by_guid(test_ctx, test_ctx->domain,
                                    test_guid, &result);
    sss_ck_fail_if_msg(ret != EOK, "GPO not in cache after modify op");
    sss_ck_fail_if_msg(result == NULL, "Could not get GPOs by guid: %s", test_guid);
    ck_assert_int_eq(result->count, 1);

    guid = ldb_msg_find_attr_as_string(result->msgs[0],
                                       SYSDB_GPO_GUID_ATTR, NULL);
    ck_assert_str_eq(guid, test_guid);

    version = ldb_msg_find_attr_as_uint(result->msgs[0],
                                        SYSDB_GPO_VERSION_ATTR, 0);
    ck_assert_int_eq(version, 2);
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_gpo_result)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *allow_key = "SeRemoteInteractiveLogonRight";
    const char *deny_key = "SeDenyRemoteInteractiveLogonRight";
    const char *value = NULL;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not setup the test");

    /* No result in cache */
    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           allow_key, &value);
    ck_assert_int_eq(ret, ENOENT);

    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           deny_key, &value);
    ck_assert_int_eq(ret, ENOENT);

    /* Delete with no result object is a noop */
    ret = sysdb_gpo_delete_gpo_result_object(test_ctx, test_ctx->domain);
    ck_assert_int_eq(ret, EOK);

    /* Store an allow value, triggering a new result object */
    ret = sysdb_gpo_store_gpo_result_setting(test_ctx->domain,
                                             allow_key, "allow_val1");
    ck_assert_int_eq(ret, EOK);

    /* Now both searches should succeed, but only allow_key should return
     * a valid value
     */
    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           allow_key, &value);
    ck_assert_int_eq(ret, EOK);
    ck_assert_str_eq(value, "allow_val1");

    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           deny_key, &value);
    ck_assert_int_eq(ret, EOK);
    ck_assert_msg(value == NULL, "Unexpected value returned for deny key "
                               "from sysdb_gpo_get_gpo_result_setting");

    /* Updating replaces the original value */
    ret = sysdb_gpo_store_gpo_result_setting(test_ctx->domain,
                                             allow_key, "allow_val2");
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           allow_key, &value);
    ck_assert_int_eq(ret, EOK);
    ck_assert_str_eq(value, "allow_val2");

    /* NULL removes the value completely */
    ret = sysdb_gpo_store_gpo_result_setting(test_ctx->domain,
                                             allow_key, NULL);
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           allow_key, &value);
    ck_assert_int_eq(ret, EOK);
    ck_assert_msg(value == NULL, "Unexpected value returned for allow key"
                               "from sysdb_gpo_get_gpo_result_setting" );

    /* Delete the result */
    ret = sysdb_gpo_delete_gpo_result_object(test_ctx, test_ctx->domain);
    ck_assert_int_eq(ret, EOK);

    /* No result in cache */
    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           allow_key, &value);
    ck_assert_int_eq(ret, ENOENT);

    ret = sysdb_gpo_get_gpo_result_setting(test_ctx, test_ctx->domain,
                                           deny_key, &value);
    ck_assert_int_eq(ret, ENOENT);
}
END_TEST

START_TEST(test_confdb_list_all_domain_names_multi_dom)
{
    int ret;
    TALLOC_CTX *tmp_ctx;
    struct confdb_ctx *confdb;
    char **names;

    const char *val[2];
    val[1] = NULL;

    tmp_ctx = talloc_new(NULL);
    ck_assert(tmp_ctx != NULL);

    confdb = test_cdb_domains_prep(tmp_ctx);
    ck_assert(confdb != NULL);

    /* Two domains */
    val[0] = "FILES";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "proxy";
    ret = confdb_add_param(confdb, true,
                           "config/domain/FILES", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "REMOTE";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "proxy";
    ret = confdb_add_param(confdb, true,
                           "config/domain/REMOTE", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    ck_assert_int_eq(ret, EOK);
    ck_assert(names != NULL);
    ck_assert_str_eq(names[0], "FILES");
    ck_assert_str_eq(names[1], "REMOTE");
    ck_assert(names[2] == NULL);
    talloc_free(tmp_ctx);
}
END_TEST

START_TEST(test_sysdb_mark_entry_as_expired_ldb_dn)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *attrs[] = { SYSDB_CACHE_EXPIRE, NULL };
    size_t count;
    struct ldb_message **msgs;
    uint64_t expire;
    struct ldb_dn *userdn;
    struct test_data *data;
    char *filter;

    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not setup the test");

    /* Add something to database to test against */
    data = test_data_new_user(test_ctx, 2000);
    sss_ck_fail_if_msg(data == NULL, "Failed to allocate memory");

    ret = sysdb_transaction_start(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);

    ret = test_add_user(data);
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);

    filter = talloc_asprintf(data,
                             "("SYSDB_UIDNUM"=%llu)",
                             (unsigned long long) data->uid);
    sss_ck_fail_if_msg(filter == NULL, "Failed to allocate memory");

    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_zfree(filter);
    ck_assert_int_eq(ret, EOK);
    ck_assert_int_eq(count, 1);

    expire = ldb_msg_find_attr_as_uint64(msgs[0], SYSDB_CACHE_EXPIRE, 0);
    ck_assert(expire != 1);

    userdn = sysdb_user_dn(test_ctx, test_ctx->domain,
                           data->username);
    ck_assert(userdn != NULL);

    ret = sysdb_transaction_start(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);

    /* Expire entry */
    ret = sysdb_mark_entry_as_expired_ldb_dn(test_ctx->domain, userdn);
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);

    filter = talloc_asprintf(data,
                             "("SYSDB_UIDNUM"=%llu)",
                             (unsigned long long) data->uid);
    sss_ck_fail_if_msg(filter == NULL, "Failed to allocate memory");

    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_zfree(filter);
    ck_assert_int_eq(ret, EOK);
    ck_assert_int_eq(count, 1);

    expire = ldb_msg_find_attr_as_uint64(msgs[0], SYSDB_CACHE_EXPIRE, 0);
    ck_assert_int_eq(expire, 1);

    /* Try to expire already expired entry. Should return EOK. */
    ret = sysdb_transaction_start(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_mark_entry_as_expired_ldb_dn(test_ctx->domain, userdn);
    ck_assert_int_eq(ret, EOK);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    ck_assert_int_eq(ret, EOK);
}
END_TEST

void hosts_check_match(struct sysdb_test_ctx *test_ctx,
                       bool by_name,
                       const char *search,
                       const char *primary_name,
                       const char **aliases,
                       const char **addresses)
{
    errno_t ret;
    unsigned int i, j;
    bool matched;
    const char *ret_name;
    struct ldb_result *res;
    struct ldb_message *msg;
    struct ldb_message_element *el;
    size_t len;

    if (by_name) {
        /* Look up the host by name */
        ret = sysdb_gethostbyname(test_ctx, test_ctx->domain, search, &res);
        sss_ck_fail_if_msg(ret != EOK, "sysdb_gethostbyname error [%s]\n",
                             strerror(ret));
    } else {
        /* Look up the host by address */
        ret = sysdb_gethostbyaddr(test_ctx, test_ctx->domain, search, &res);
        sss_ck_fail_if_msg(ret != EOK, "sysdb_gethostbyaddr error [%s]\n",
                             strerror(ret));
    }
    sss_ck_fail_if_msg(res == NULL, "ENOMEM");
    ck_assert_int_eq(res->count, 1);

    /* Make sure the returned entry matches */
    msg = res->msgs[0];
    ret_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    sss_ck_fail_if_msg(ret_name == NULL, "Failed to find attribute: " SYSDB_NAME);
    ck_assert_msg(strcmp(ret_name, primary_name) == 0,
                "Wrong value returned for attribute: %s. got: %s expected: %s",
                SYSDB_NAME, ret_name, primary_name);

    el = ldb_msg_find_element(msg, SYSDB_IP_HOST_ATTR_ADDRESS);
    sss_ck_fail_if_msg(el == NULL, "Failed to find elemeny: " SYSDB_IP_HOST_ATTR_ADDRESS);

    len = talloc_array_length(addresses);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; j < len && addresses[j] != NULL; j++) {
            char *canonical_address;
            ret = sss_canonicalize_ip_address(test_ctx, addresses[j],
                                              &canonical_address);
            sss_ck_fail_if_msg(ret != EOK,
                     "sss_canonicalize_ip_address failed: %d", ret);

            if (strcmp(canonical_address,
                      (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }

        sss_ck_fail_if_msg(!matched, "Unexpected value in LDB entry: [%s]",
                (const char *)el->values[i].data);
    }

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    sss_ck_fail_if_msg(el == NULL, "Failed to find element: " SYSDB_NAME_ALIAS);

    len = talloc_array_length(aliases);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; j < len && aliases[j] != NULL; j++) {
            if (strcmp(aliases[j], (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }
        sss_ck_fail_if_msg(!matched, "Unexpected value in LDB entry: [%s]",
                (const char *)el->values[i].data);
    }
}

#define hosts_check_match_name(test_ctx, search_name, primary_name, aliases, addresses) \
    do { \
        hosts_check_match(test_ctx, true, search_name, primary_name, aliases, addresses); \
    } while(0);

#define hosts_check_match_address(test_ctx, search_name, primary_name, aliases, addresses) \
    do { \
        hosts_check_match(test_ctx, false, search_name, primary_name, aliases, addresses); \
    } while(0);

START_TEST(test_sysdb_add_hosts)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    char *primary_name;
    const char **aliases;
    const char **addresses;
    int i;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    primary_name = talloc_asprintf(test_ctx, "test.example.org");
    sss_ck_fail_if_msg(primary_name == NULL, "Failed to allocate memory");

    aliases = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(aliases == NULL, "Failed to allocate memory");

    aliases[0] = talloc_asprintf(aliases, "alias1.example.org");
    sss_ck_fail_if_msg(aliases[0] == NULL, "Failed to allocate memory");

    aliases[1] = talloc_asprintf(aliases, "alias2.example.org");
    sss_ck_fail_if_msg(aliases[1] == NULL, "Failed to allocate memory");

    aliases[2] = NULL;

    addresses = talloc_array(test_ctx, const char *, 6);
    sss_ck_fail_if_msg(addresses == NULL, "Failed to allocate memory");

    addresses[0] = talloc_asprintf(addresses, "1.1.2.3");
    sss_ck_fail_if_msg(addresses[0] == NULL, "Failed to allocate memory");

    addresses[1] = talloc_asprintf(addresses, "10.11.22.33");
    sss_ck_fail_if_msg(addresses[1] == NULL, "Failed to allocate memory");

    addresses[2] = talloc_asprintf(addresses, "100.123.123.123");
    sss_ck_fail_if_msg(addresses[2] == NULL, "Failed to allocate memory");

    addresses[3] = talloc_asprintf(addresses, "2001:0db8:85a3:0000:0000:8a2e:0370:7334");
    sss_ck_fail_if_msg(addresses[3] == NULL, "Failed to allocate memory");

    addresses[4] = talloc_asprintf(addresses, "2001:db8:85a3:0:1:8a2e:370:7334");
    sss_ck_fail_if_msg(addresses[4] == NULL, "Failed to allocate memory");

    addresses[5] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_host_add(NULL, test_ctx->domain,
                         primary_name, aliases,
                         addresses, NULL);
    ck_assert_msg(ret == EOK, "sysdb_host_add error [%s]\n", strerror(ret));

    /* Search by name and make sure the results match */
    hosts_check_match_name(test_ctx, primary_name, primary_name,
                           aliases, addresses);
    for (i = 0; aliases[i] != NULL; i++) {
        hosts_check_match_name(test_ctx, aliases[i], primary_name,
                               aliases, addresses);
    }

    /* Search by address and make sure the results match */
    for (i = 0; addresses[i] != NULL; i++) {
        hosts_check_match_address(test_ctx, addresses[i], primary_name,
                                  aliases, addresses);
    }

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by name)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_host_delete(test_ctx->domain, primary_name, NULL);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

void ipnetwork_check_match(struct sysdb_test_ctx *test_ctx,
                           struct ldb_message *msg,
                           const char *primary_name,
                           const char **aliases,
                           const char *address)

{
    errno_t ret;
    const char *ret_name;
    const char *ret_addr;
    char *c_addr;
    struct ldb_message_element *el;
    size_t len;
    unsigned int i, j;
    bool matched;

    ret = sss_canonicalize_ip_address(test_ctx, address, &c_addr);
    sss_ck_fail_if_msg(ret != EOK, "sss_canonicalize_ip_address failed: %d", ret);

    ret_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    sss_ck_fail_if_msg(ret_name == NULL, "Failed to find attribue: " SYSDB_NAME);
    ck_assert_msg(strcmp(ret_name, primary_name) == 0,
                "Wrong value returned for attribute: %s. got: %s expected: %s",
                SYSDB_NAME, ret_name, primary_name);

    ret_addr = ldb_msg_find_attr_as_string(msg, SYSDB_IP_NETWORK_ATTR_NUMBER,
                                           NULL);
    sss_ck_fail_if_msg(ret_addr == NULL,
            "Failed to find attribue: " SYSDB_IP_NETWORK_ATTR_NUMBER);
    ck_assert_msg(strcmp(ret_addr, c_addr) == 0,
                "Wrong value returned for attribute: %s. got: %s expected: %s",
                SYSDB_IP_NETWORK_ATTR_NUMBER, ret_addr, c_addr);

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    sss_ck_fail_if_msg(el == NULL, "Failed to find element: " SYSDB_NAME_ALIAS);

    len = talloc_array_length(aliases);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; j < len && aliases[j] != NULL; j++) {
            if (strcmp(aliases[j], (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }
        sss_ck_fail_if_msg(!matched, "Unexpected value in LDB entry: [%s]",
                (const char *)el->values[i].data);
    }
}

void ipnetwork_check_match_name(struct sysdb_test_ctx *test_ctx,
                                const char *search_name,
                                const char *primary_name,
                                const char **aliases,
				const char *address)
{
    errno_t ret;
    struct ldb_result *res;

    ret = sysdb_getipnetworkbyname(test_ctx, test_ctx->domain,
                                   search_name, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_getipnetworkbyname error [%s]\n",
            strerror(ret));
    sss_ck_fail_if_msg(res == NULL, "ENOMEM");
    ck_assert_int_eq(res->count, 1);

    ipnetwork_check_match(test_ctx, res->msgs[0], primary_name, aliases,
			  address);
}

void ipnetwork_check_match_addr(struct sysdb_test_ctx *test_ctx,
                                const char *search_addr,
                                const char *primary_name,
                                const char **aliases,
                                const char *address)
{
    errno_t ret;
    struct ldb_result *res;

    ret = sysdb_getipnetworkbyaddr(test_ctx, test_ctx->domain,
                                   search_addr, &res);
    sss_ck_fail_if_msg(ret != EOK, "sysdb_getipnetworkbyaddr error [%s]\n",
            strerror(ret));
    sss_ck_fail_if_msg(res == NULL, "ENOMEM");
    ck_assert_int_eq(res->count, 1);

    ipnetwork_check_match(test_ctx, res->msgs[0], primary_name, aliases,
			  address);
}

START_TEST(test_sysdb_add_ipnetworks)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    char *primary_name;
    const char **aliases;
    const char *address;
    int i;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    sss_ck_fail_if_msg(ret != EOK, "Could not set up the test");

    primary_name = talloc_asprintf(test_ctx, "network_1");
    sss_ck_fail_if_msg(primary_name == NULL, "Failed to allocate memory");

    aliases = talloc_array(test_ctx, const char *, 3);
    sss_ck_fail_if_msg(aliases == NULL, "Failed to allocate memory");

    aliases[0] = talloc_asprintf(aliases, "network_1_alias_1");
    sss_ck_fail_if_msg(aliases[0] == NULL, "Failed to allocate memory");

    aliases[1] = talloc_asprintf(aliases, "network_1_alias_2");
    sss_ck_fail_if_msg(aliases[1] == NULL, "Failed to allocate memory");

    aliases[2] = NULL;

    address = talloc_asprintf(test_ctx, "192.168.1.0");
    sss_ck_fail_if_msg(address == NULL, "Failed to allocate memory");

    ret = sysdb_transaction_start(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_ipnetwork_add(NULL, test_ctx->domain,
                              primary_name, aliases,
                              address, NULL);
    ck_assert_msg(ret == EOK, "sysdb_ipnetwork_add error [%s]\n", strerror(ret));

    /* Search by name and make sure the results match */
    ipnetwork_check_match_name(test_ctx, primary_name, primary_name,
                               aliases, address);
    for (i = 0; aliases[i] != NULL; i++) {
        ipnetwork_check_match_name(test_ctx, aliases[i], primary_name,
                                   aliases, address);
    }

    /* Search by address and make sure the results match */
    ipnetwork_check_match_addr(test_ctx, address, primary_name,
                               aliases, address);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by name)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_ipnetwork_delete(test_ctx->domain, primary_name, NULL);
    sss_ck_fail_if_msg(ret != EOK, "[%s]", strerror(ret));

    talloc_free(test_ctx);
}
END_TEST


Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* Add a user with an automatic ID */
    tcase_add_test(tc_sysdb, test_sysdb_user_new_id);

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_user, 27000, 27010);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27000, 27010);

    /* Since this is a local (mpg) domain, verify the user groups
     * can be found. Regression test for ticket #3615
     */
    tcase_add_loop_test(tc_sysdb, test_user_group_by_name, 27000, 27010);
    tcase_add_loop_test(tc_sysdb, test_user_group_by_name_local, 27000, 27010);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group, 28000, 28010);

    /* Verify the groups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrnam, 28000, 28010);

    /* sysdb_group_dn_name returns the name of the group in question */
    tcase_add_loop_test(tc_sysdb, test_sysdb_group_dn_name, 28000, 28010);

    /* sysdb_store_user allows setting attributes for existing users */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_user_existing, 27000, 27010);

    /* test the change */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_user_attr, 27000, 27010);

    /* Add and remove users in a group with sysdb_update_members */
    tcase_add_test(tc_sysdb, test_sysdb_update_members);

    /* Remove the other half by gid */
    tcase_add_loop_test(tc_sysdb,
                        test_sysdb_remove_local_group_by_gid,
                        28000, 28010);

    /* Remove the other half by uid */
    tcase_add_loop_test(tc_sysdb,
                        test_sysdb_remove_local_user_by_uid,
                        27000, 27010);

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_user, 27010, 27020);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27010, 27020);

    /* Verify the users can be queried by UID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwuid, 27010, 27020);

    /* Enumerate the users */
    tcase_add_test(tc_sysdb, test_sysdb_enumpwent);

    /* Change their attribute */
    tcase_add_loop_test(tc_sysdb, test_sysdb_set_user_attr, 27010, 27020);

    /* Find the users by their new attribute */
    tcase_add_loop_test(tc_sysdb, test_sysdb_search_users, 27010, 27020);

    /* Verify the change */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_user_attr, 27010, 27020);

    /* Remove the attribute */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_attrs, 27010, 27020);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_group, 28010, 28020);

    /* Verify the groups were added */

    /* Verify the groups can be queried by GID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrgid, 28010, 28020);
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrgid_attrs, 28010, 28020);

    /* Find the users by GID using a filter */
    tcase_add_loop_test(tc_sysdb, test_sysdb_search_groups, 28010, 28020);

    /* Enumerate the groups */
    tcase_add_test(tc_sysdb, test_sysdb_enumgrent);

    /* Add some members to the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group_member, 28010, 28020);

    /* Test that sysdb_initgroups() works */
    tcase_add_loop_test(tc_sysdb, test_sysdb_initgroups, 27010, 27020);

    /* Authenticate with missing cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication_missing_password,
                        27010, 27011);

    /* Add a cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cache_password, 27010, 27011);

    /* Authenticate against cached password */
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication_wrong_password,
                        27010, 27011);
    tcase_add_loop_test(tc_sysdb, test_sysdb_cached_authentication, 27010, 27011);

    tcase_add_loop_test(tc_sysdb, test_sysdb_cache_password_ex, 27010, 27011);

    /* ASQ search test */
    tcase_add_loop_test(tc_sysdb, test_sysdb_prepare_asq_test_user, 28011, 28020);
    tcase_add_test(tc_sysdb, test_sysdb_asq_search);

    /* Test search with more than one result */
    tcase_add_test(tc_sysdb, test_sysdb_search_all_users);

    /* Remove the members from the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_group_member, 28010, 28020);

    /* Remove the users by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user, 27010, 27020);

    /* Remove the groups by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group, 28010, 28020);

    /* test the ignore_not_found parameter for users */
    tcase_add_test(tc_sysdb, test_sysdb_remove_nonexistent_user);

    /* test the ignore_not_found parameter for groups */
    tcase_add_test(tc_sysdb, test_sysdb_remove_nonexistent_group);

    /* Create incomplete groups - remove will fail if the LDB objects
     * don't exist
     */
    tcase_add_loop_test(tc_sysdb,
                        test_sysdb_add_incomplete_group,
                        28000, 28010);
    tcase_add_loop_test(tc_sysdb,
                        test_sysdb_remove_local_group_by_gid,
                        28000, 28010);
    tcase_add_test(tc_sysdb, test_sysdb_incomplete_group_rename);

    /* test custom operations */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_custom, 29010, 29020);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_by_name);
    tcase_add_test(tc_sysdb, test_sysdb_update_custom);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_update);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom);
    tcase_add_test(tc_sysdb, test_sysdb_delete_custom);
    tcase_add_test(tc_sysdb, test_sysdb_delete_by_sid);

    /* test recursive delete */
    tcase_add_test(tc_sysdb, test_sysdb_delete_recursive);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_replace_name);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_to_list);

    /* Test unusual characters */
    tcase_add_test(tc_sysdb, test_odd_characters);

    /* Test sysdb enumerated flag */
    tcase_add_test(tc_sysdb, test_sysdb_has_enumerated);

    /* Test originalDN searches */
    tcase_add_test(tc_sysdb, test_sysdb_original_dn_case_insensitive);

    /* Test sysdb_search_groups_by_orig_dn */
    tcase_add_test(tc_sysdb, test_sysdb_search_groups_by_orig_dn);

    /* Test sysdb_search_users_by_orig_dn */
    tcase_add_test(tc_sysdb, test_sysdb_search_users_by_orig_dn);

    /* Test SID string searches */
    tcase_add_test(tc_sysdb, test_sysdb_search_sid_str);

    /* Test object by ID searches */
    tcase_add_test(tc_sysdb, test_sysdb_search_object_by_id);

    /* Test UUID string searches */
    tcase_add_test(tc_sysdb, test_sysdb_search_object_by_uuid);

    /* Test object by name */
    tcase_add_test(tc_sysdb, test_sysdb_search_object_by_name);

    /* Test user by certificate searches */
    tcase_add_test(tc_sysdb, test_sysdb_search_user_by_cert);

    /* Test canonicalizing names */
    tcase_add_test(tc_sysdb, test_sysdb_get_real_name);

    /* Test user and group renames */
    tcase_add_test(tc_sysdb, test_group_rename);
    tcase_add_test(tc_sysdb, test_user_rename);

    /* Test GetUserAttr with subdomain user */
    tcase_add_test(tc_sysdb, test_sysdb_get_user_attr_subdomain);

    /* Test adding a non-POSIX user and group */
    tcase_add_test(tc_sysdb, test_sysdb_add_nonposix_user);
    tcase_add_test(tc_sysdb, test_sysdb_add_nonposix_group);

/* ===== NETGROUP TESTS ===== */

    /* Create a new netgroup */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_basic_netgroup, 27000, 27010);

    /* Verify the netgroups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_search_netgroup_by_name, 27000, 27010);

    /* Test setting attributes */
    tcase_add_loop_test(tc_sysdb, test_sysdb_set_netgroup_attr, 27000, 27010);

    /* Verify they have been changed */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_netgroup_attr, 27000, 27010);

    /* Remove half of them by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_by_name, 27000, 27005);

    /* Remove the other half by DN */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_netgroup_entry, 27005, 27010);

    tcase_add_test(tc_sysdb, test_netgroup_base_dn);

    /* Test splitting the netgroup triple */
    tcase_add_test(tc_sysdb, test_sysdb_netgr_to_entries);

/* ===== SERVICE TESTS ===== */

    /* Create a new service */
    tcase_add_test(tc_sysdb, test_sysdb_add_services);
    tcase_add_test(tc_sysdb, test_sysdb_store_services);
    tcase_add_test(tc_sysdb, test_sysdb_svc_remove_alias);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_lc_name_alias);
    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_lc_name_alias_safe);

/* ===== UTIL TESTS ===== */
    tcase_add_test(tc_sysdb, test_sysdb_attrs_get_string_array);
    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_val);
    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_val_safe);
    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_string_safe);
    tcase_add_test(tc_sysdb, test_sysdb_attrs_copy);

/* ===== Test search return empty result ===== */
    tcase_add_test(tc_sysdb, test_sysdb_search_return_ENOENT);

/* ===== Misc ===== */
    tcase_add_test(tc_sysdb, test_sysdb_set_get_bool);
    tcase_add_test(tc_sysdb, test_sysdb_set_get_uint);
    tcase_add_test(tc_sysdb, test_sysdb_mark_entry_as_expired_ldb_dn);

/* ===== Hosts tests ===== */
    tcase_add_test(tc_sysdb, test_sysdb_add_hosts);

/* ===== IP Networks tests ===== */
    tcase_add_test(tc_sysdb, test_sysdb_add_ipnetworks);

/* Add all test cases to the test suite */
    suite_add_tcase(s, tc_sysdb);

    TCase *tc_memberof = tcase_create("SYSDB member/memberof/memberuid Tests");

    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_user, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_add_group_member,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_memberuid,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE + 5, MBO_GROUP_BASE + 6);
    tcase_add_loop_test(tc_memberof,
                        test_sysdb_memberof_check_memberuid_without_group_5,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 5);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE+6 , MBO_GROUP_BASE + 10);

    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group, 0, 10);
    tcase_add_test(tc_memberof, test_sysdb_memberof_close_loop);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_user, 0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_add_group_member,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_memberuid_loop,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE + 5, MBO_GROUP_BASE + 6);
    tcase_add_loop_test(tc_memberof,
                        test_sysdb_memberof_check_memberuid_loop_without_group_5,
                        0, 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 5);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE+6 , MBO_GROUP_BASE + 10);

    /* Ghost users tests */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group_with_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_nested_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_remove_child_group_and_check_ghost,
                        MBO_GROUP_BASE + 1, MBO_GROUP_BASE + 10);
    /* Only one group should be left now */
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE + 9 , MBO_GROUP_BASE + 10);

    /* ghost users - RFC2307 */
    /* Add groups with ghost users */
    tcase_add_loop_test(tc_memberof, test_sysdb_add_group_with_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    /* Check the ghost user attribute */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_ghost,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    /* Add user entries, converting the ghost attributes to member attributes */
    /* We only convert half of the users and keep the ghost attributes for the
     * other half as we also want to test if we don't delete any ghost users
     * by accident
     */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_convert_to_real_users,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + NUM_GHOSTS/2);
    /* Check the members and ghosts are there as appropriate */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_convert,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + NUM_GHOSTS);
    /* Rename the other half */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_ghost_replace,
                        MBO_GROUP_BASE + NUM_GHOSTS/2 + 1,
                        MBO_GROUP_BASE + NUM_GHOSTS);
    /* Attempt to replace with the same data to check if noop works correctly */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_ghost_replace_noop,
                        MBO_GROUP_BASE + NUM_GHOSTS/2 + 1,
                        MBO_GROUP_BASE + NUM_GHOSTS);

    /* Remove the real users */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_user_cleanup,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + NUM_GHOSTS/2);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + NUM_GHOSTS);

    /* ghost users - memberof mod_del */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group_with_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_nested_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_mod_del,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + NUM_GHOSTS);

    /* ghost users - memberof mod_add */
    /* Add groups without ghosts first */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group, 0, 10);
    /* Add ghosts to groups so that they propagate */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_mod_add,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    /* Check if the ghosts in fact propagated */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_nested_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    /* Clean up */
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    /* ghost users - replace */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group_with_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_nested_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_mod_replace,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    /* ghost users - replace but retain inherited */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_store_group_with_double_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_check_nested_double_ghosts,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    /* SSS_LDB_SEARCH */
    tcase_add_test(tc_sysdb, test_SSS_LDB_SEARCH);

    /* This loop counts backwards so the indexing is a little odd */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_mod_replace_keep,
                        1 , 11);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);
    suite_add_tcase(s, tc_memberof);

    TCase *tc_subdomain = tcase_create("SYSDB sub-domain Tests");

    tcase_add_test(tc_subdomain, test_sysdb_subdomain_store_user);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_content_delete);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_user_ops);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_group_ops);

    suite_add_tcase(s, tc_subdomain);

#ifdef BUILD_AUTOFS
    TCase *tc_autofs = tcase_create("SYSDB autofs Tests");

    tcase_add_loop_test(tc_autofs, test_autofs_create_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_retrieve_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_store_entry_in_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_retrieve_keys_by_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_delete_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_retrieve_map_neg,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_autofs, test_autofs_key_duplicate,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_test(tc_autofs, test_autofs_get_duplicate_keys);

    suite_add_tcase(s, tc_autofs);
#endif

    TCase *tc_upn = tcase_create("SYSDB UPN tests");
    tcase_add_test(tc_upn, test_upn_basic);
    tcase_add_test(tc_upn, test_upn_basic_case);
    tcase_add_test(tc_upn, test_upn_canon);
    tcase_add_test(tc_upn, test_upn_canon_case);
    tcase_add_test(tc_upn, test_upn_dup);

    suite_add_tcase(s, tc_upn);

    TCase *tc_gpo = tcase_create("SYSDB GPO tests");
    tcase_add_test(tc_gpo, test_gpo_store_retrieve);
    tcase_add_test(tc_gpo, test_gpo_replace);
    tcase_add_test(tc_gpo, test_gpo_result);
    suite_add_tcase(s, tc_gpo);

    /* ConfDB tests -- modify confdb, must always be last!! */
    TCase *tc_confdb = tcase_create("confDB tests");

    tcase_add_test(tc_confdb, test_confdb_list_all_domain_names_no_dom);
    tcase_add_test(tc_confdb, test_confdb_list_all_domain_names_single_dom);
    tcase_add_test(tc_confdb, test_confdb_list_all_domain_names_multi_dom);
    suite_add_tcase(s, tc_confdb);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
    poptContext pc;
    int failure_count;
    int no_cleanup = 0;
    Suite *sysdb_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
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

    if (!ldb_modules_path_is_set()) {
        fprintf(stderr, "Warning: LDB_MODULES_PATH is not set, "
                "will use LDB plugins installed in system paths.\n");
    }

    tests_set_cwd();
    talloc_enable_null_tracking();

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (failure_count == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, "FILES");
    }
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
