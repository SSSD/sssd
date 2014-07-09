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
#include <popt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include "util/util.h"
#include "confdb/confdb_setup.h"
#include "db/sysdb_private.h"
#include "db/sysdb_services.h"
#include "db/sysdb_autofs.h"
#include "tests/common.h"

#define TESTS_PATH "tests_sysdb"
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
        fail("Could not create %s directory", TESTS_PATH);
        return EFAULT;
    }

    test_ctx = talloc_zero(NULL, struct sysdb_test_ctx);
    if (test_ctx == NULL) {
        fail("Could not allocate memory for test context");
        return ENOMEM;
    }

    /* Create an event context
     * It will not be used except in confdb_init and sysdb_init
     */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        fail("Could not create event context");
        talloc_free(test_ctx);
        return EIO;
    }

    conf_db = talloc_asprintf(test_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    if (conf_db == NULL) {
        fail("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(SSSDBG_MINOR_FAILURE, "CONFDB: %s\n", conf_db);

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, &test_ctx->confdb, conf_db);
    if (ret != EOK) {
        fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/sssd", "domains", val);
    if (ret != EOK) {
        fail("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = enumerate ? "TRUE" : "FALSE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "enumerate", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domain/LOCAL", "cache_credentials", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sssd_domain_init(test_ctx, test_ctx->confdb, "local",
                           TESTS_PATH, &test_ctx->domain);
    if (ret != EOK) {
        fail("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }
    test_ctx->sysdb = test_ctx->domain->sysdb;

    *ctx = test_ctx;
    return EOK;
}

#define setup_sysdb_tests(ctx) _setup_sysdb_tests((ctx), false)

struct test_data {
    struct tevent_context *ev;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    const char *netgrname;
    const char *autofsmapname;
    uid_t uid;
    gid_t gid;
    const char *shell;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char **attrlist;
    char **memberlist;
    struct ldb_message *msg;

    size_t msgs_count;
    struct ldb_message **msgs;
};

static int test_add_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    ret = sysdb_add_user(data->ctx->domain, data->username,
                         data->uid, 0, gecos, homedir, "/bin/bash",
                         NULL, NULL, 0, 0);
    return ret;
}

static int test_store_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

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

    user_dn = sysdb_user_dn(data, data->ctx->domain, data->username);
    if (!user_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, user_dn, true);
    return ret;
}

static int test_remove_user_by_uid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_group(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_user(struct test_data *data)
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
                                     data->gid, NULL, NULL, true, 0);
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

    group_dn = sysdb_group_dn(data, data->ctx->domain, data->groupname);
    if (!group_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, group_dn, true);
    return ret;
}

static int test_remove_group_by_gid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data->ctx->domain, NULL, data->gid);
    if (ret == ENOENT) {
        ret = EOK;
    }
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
    const char *username;
    int ret;

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        return ENOMEM;
    }

    ret = sysdb_add_group_member(data->ctx->domain,
                                 data->groupname, username,
                                 SYSDB_MEMBER_USER, false);
    return ret;
}

static int test_remove_group_member(struct test_data *data)
{
    const char *username;
    int ret;

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        return ENOMEM;
    }

    ret = sysdb_remove_group_member(data->ctx->domain,
                                    data->groupname, username,
                                    SYSDB_MEMBER_USER, false);
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
                             "LOCAL");
    if (base_dn == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_entry(data, data->ctx->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, "objectClass=user",
                             data->attrlist, &data->msgs_count, &data->msgs);
    return ret;
}

static int test_delete_recursive(struct test_data *data)
{
    struct ldb_dn *dn;
    int ret;

    dn = ldb_dn_new_fmt(data, data->ctx->sysdb->ldb, SYSDB_DOM_BASE,
                        "LOCAL");
    if (!dn) {
        return ENOMEM;
    }

    ret = sysdb_delete_recursive(data->ctx->sysdb, dn, false);
    fail_unless(ret == EOK, "sysdb_delete_recursive returned [%d]", ret);
    return ret;
}

static int test_memberof_store_group(struct test_data *data)
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

    ret = sysdb_store_group(data->ctx->domain,
                            data->groupname, data->gid, attrs, -1, 0);
    return ret;
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

    for (i = 0; data->memberlist && data->memberlist[i]; i++) {
        ret = sysdb_attrs_steal_string(attrs, SYSDB_GHOST,
                                       data->memberlist[i]);
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

START_TEST (test_sysdb_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->shell = talloc_asprintf(data, "/bin/ksh");

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", _i);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_remove_user(data);

    fail_if(ret != EOK, "Could not remove user %s", data->username);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;

    ret = test_remove_user_by_uid(data);

    fail_if(ret != EOK, "Could not remove user with uid %d", _i);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_remove_group(data);

    fail_if(ret != EOK, "Could not remove group %s", data->groupname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    ret = test_remove_group_by_gid(data);

    fail_if(ret != EOK, "Could not remove group with gid %d", _i);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = test_add_user(data);

    fail_if(ret != EOK, "Could not add user %s", data->username);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_add_group(data);

    fail_if(ret != EOK, "Could not add group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group_with_ghosts)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    char *membername;
    int j;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    fail_unless(data->groupname != NULL, "Out of memory\n");

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    for (j = MBO_GROUP_BASE; j < _i; j++) {
        membername = talloc_asprintf(data, "testghost%d", j);
        fail_unless(membername != NULL, "Out of memory\n");
        ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, membername);
        if (ret != EOK) {
            fail_unless(ret == EOK, "Cannot add attr\n");
        }
    }

    ret = test_store_group(data);

    fail_if(ret != EOK, "Could not add group %s", data->groupname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = test_add_incomplete_group(data);

    fail_if(ret != EOK, "Could not add incomplete group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *username;
    uid_t uid;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         username, &res);
    if (ret) {
        fail("sysdb_getpwnam failed for username %s (%d: %s)",
             username, ret, strerror(ret));
        goto done;
    }

    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    fail_unless(uid == _i, "Did not find the expected UID");

    /* Search for the user with the wrong case */
    username = talloc_asprintf(test_ctx, "TESTUSER%d", _i);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         username, &res);
    if (ret) {
        fail("sysdb_getpwnam failed for username %s (%d: %s)",
             username, ret, strerror(ret));
        goto done;
    }

    if (res->count != 0) {
        fail("The upper-case username search should fail.");
    }

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrnam)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *groupname;
    gid_t gid;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->domain,
                         groupname, &res);
    if (ret) {
        fail("sysdb_getgrnam failed for groupname %s (%d: %s)",
             groupname, ret, strerror(ret));
        goto done;
    }

    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    fail_unless(gid == _i,
                "Did not find the expected GID (found %d expected %d)",
                gid, _i);

    /* Search for the group with the wrong case */
    groupname = talloc_asprintf(test_ctx, "TESTGROUP%d", _i);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->domain,
                         groupname, &res);
    if (ret) {
        fail("sysdb_getgrnam failed for groupname %s (%d: %s)",
             groupname, ret, strerror(ret));
        goto done;
    }

    if (res->count != 0) {
        fail("The upper-case groupname search should fail.");
    }

done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrgid)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *e_groupname;
    const char *groupname;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_getgrgid(test_ctx,
                         test_ctx->domain,
                         _i, &res);
    if (ret) {
        fail("sysdb_getgrgid failed for gid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

    groupname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);

    e_groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    if (e_groupname == NULL) {
        fail("Cannot allocate memory");
        goto done;
    }

    fail_unless(strcmp(groupname, e_groupname) == 0,
                "Did not find the expected groupname (found %s expected %s)",
                groupname, e_groupname);
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
    fail_if(ret != EOK, "Could not set up the test");

    filter = talloc_asprintf(test_ctx, "("SYSDB_GIDNUM"=%d)", _i);
    fail_if(filter == NULL, "OOM");

    ret = sysdb_search_groups(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_free(filter);
    fail_if(ret != EOK, "Search failed: %d", ret);
    fail_if(count != 1, "Did not find the expected group\n");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    const char *e_username;
    const char *username;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_getpwuid(test_ctx,
                         test_ctx->domain,
                         _i, &res);
    if (ret) {
        fail("sysdb_getpwuid failed for uid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

    fail_unless(res->count == 1, "Expected 1 user entry, found %d\n",
                res->count);

    username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);

    e_username = talloc_asprintf(test_ctx, "testuser%d", _i);
    if (username == NULL) {
        fail("Cannot allocate memory");
        goto done;
    }

    fail_unless(strcmp(username, e_username) == 0,
                "Did not find the expected username (found %s expected %s)",
                username, e_username);
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
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_enumgrent(test_ctx,
                          test_ctx->domain,
                          &res);
    fail_unless(ret == EOK,
                "sysdb_enumgrent failed (%d: %s)",
                ret, strerror(ret));

    /* 10 groups + 10 users (we're MPG) */
    fail_if(res->count != 20, "Expected 20 users, got %d", res->count);

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
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_enumpwent(test_ctx,
                          test_ctx->domain,
                          &res);
    fail_unless(ret == EOK,
                "sysdb_enumpwent failed (%d: %s)",
                ret, strerror(ret));

    fail_if(res->count != 10, "Expected 10 users, got %d", res->count);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 SYSDB_SHELL,
                                 "/bin/ksh");
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ret = test_set_user_attr(data);

    fail_if(ret != EOK, "Could not modify user %s", data->username);

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
    fail_if(ret != EOK, "Could not set up the test");

    filter = talloc_asprintf(test_ctx,
                             "(&("SYSDB_UIDNUM"=%d)("SYSDB_SHELL"=/bin/ksh))",
                             _i);
    fail_if(filter == NULL, "OOM");

    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             filter, attrs, &count, &msgs);
    talloc_free(filter);
    fail_if(ret != EOK, "Search failed: %d", ret);
    fail_if(count != 1, "Did not find the expected user\n");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_attrs)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    char *rmattrs[2];
    char *username;
    struct ldb_result *res;
    const char *shell;

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    username = talloc_asprintf(test_ctx, "testuser%d", _i);
    fail_if(username == NULL, "OOM");

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         username, &res);
    fail_if(ret != EOK, "sysdb_getpwnam failed for username %s (%d: %s)",
                         username, ret, strerror(ret));
    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    fail_unless(shell != NULL, "Did not find user shell before removal");

    rmattrs[0] = discard_const(SYSDB_SHELL);
    rmattrs[1] = NULL;

    ret = sysdb_remove_attrs(test_ctx->domain, username, SYSDB_MEMBER_USER,
                             rmattrs);
    fail_if(ret != EOK, "Removing attributes failed: %d", ret);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->domain,
                         username, &res);
    fail_if(ret != EOK, "sysdb_getpwnam failed for username %s (%d: %s)",
                         username, ret, strerror(ret));
    shell = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, NULL);
    fail_unless(shell == NULL, "Found user shell after removal");
}
END_TEST

START_TEST (test_sysdb_get_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    const char *attrs[] = { SYSDB_SHELL, NULL };
    struct ldb_result *res;
    const char *attrval;
    char *username;
    int ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);

    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, username, attrs,
                              &res);
    if (ret) {
        fail("Could not get attributes for user %s", username);
        goto done;
    }

    fail_if(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, 0);
    fail_if(strcmp(attrval, "/bin/ksh"),
            "Got bad attribute value for user %s", username);
done:
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_initgroups)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    const char *username;
    struct ldb_result *res;
    struct ldb_message *user;
    struct ldb_message *group;
    gid_t gid;
    uid_t uid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);

    ret = sysdb_initgroups(test_ctx,
                           test_ctx->domain,
                           username, &res);
    fail_if(ret != EOK, "sysdb_initgroups failed\n");

    /* result should contain 2 messages - user and his group */
    fail_if(res->count != 2, "expected 2 groups, got %d\n", res->count);

    /* check if it's the expected user and expected group */
    user = res->msgs[0];
    group = res->msgs[1];

    uid = ldb_msg_find_attr_as_uint(user, SYSDB_UIDNUM, 0);
    fail_unless(uid == _i,
                "Did not find the expected UID (found %d expected %d)",
                uid, _i);

    fail_unless(strcmp(ldb_msg_find_attr_as_string(user, SYSDB_NAME, NULL),
                       username) == 0,
                "Wrong username\n");


    gid = ldb_msg_find_attr_as_uint(group, SYSDB_GIDNUM, 0);
    fail_unless(gid == _i + 1000,
                "Did not find the expected GID (found %d expected %d)",
                gid, _i);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */

    ret = test_remove_group_member(data);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 12345;

    ret = test_remove_nonexistent_user(data);

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 12345;

    ret = test_remove_nonexistent_group(data);

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_new_id)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    uint32_t id;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Cannot setup sysdb tests\n");

    ret = sysdb_get_new_id(test_ctx->domain, &id);
    fail_if(ret != EOK, "Cannot get new ID\n");
    fail_if(id != test_ctx->domain->id_min);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    fail_if(ret != EOK, "Could not add custom object");
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    fail_unless(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data,
                                      data->ctx->domain,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 1,
                "Wrong number of objects, exptected [1] got [%d]",
                data->msgs_count);
    fail_unless(data->msgs[0]->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msgs[0]->num_elements);
    fail_unless(strcmp(data->msgs[0]->elements[0].name, TEST_ATTR_NAME) == 0,
                "Wrong attribute name");
    fail_unless(data->msgs[0]->elements[0].num_values == 1,
                "Wrong number of attribute values");
    fail_unless(strncmp((const char *)data->msgs[0]->elements[0].values[0].data,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = 29010;
    data->attrs = sysdb_new_attrs(test_ctx);
    if (ret != EOK) {
        fail("Could not create attribute list");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_NAME,
                                 TEST_ATTR_UPDATE_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = sysdb_attrs_add_string(data->attrs,
                                 TEST_ATTR_ADD_NAME,
                                 TEST_ATTR_ADD_VALUE);
    if (ret != EOK) {
        fail("Could not add attribute");
        return;
    }

    ret = test_store_custom(data);

    fail_if(ret != EOK, "Could not add custom object");
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 3);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    object_name = talloc_asprintf(data, "%s_%d", CUSTOM_TEST_OBJECT, 29010);
    fail_unless(object_name != NULL, "talloc_asprintf failed");

    ret = sysdb_search_custom_by_name(data,
                                      data->ctx->domain,
                                      object_name,
                                      CUSTOM_TEST_CONTAINER,
                                      data->attrlist,
                                      &data->msgs_count,
                                      &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 1,
                "Wrong number of objects, exptected [1] got [%d]",
                data->msgs_count);
    fail_unless(data->msgs[0]->num_elements == 2,
                "Wrong number of results, expected [2] got [%d]",
                data->msgs[0]->num_elements);

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_NAME);
    fail_unless(el != NULL, "Attribute [%s] not found", TEST_ATTR_NAME);
    fail_unless(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_NAME);
    fail_unless(strncmp((const char *) el->values[0].data,
                TEST_ATTR_UPDATE_VALUE,
                el->values[0].length) == 0,
                "Wrong attribute value");

    el = ldb_msg_find_element(data->msgs[0], TEST_ATTR_ADD_NAME);
    fail_unless(el != NULL, "Attribute [%s] not found", TEST_ATTR_ADD_NAME);
    fail_unless(el->num_values == 1, "Wrong number ([%d] instead of 1) "
                "of attribute values for [%s]", el->num_values,
                TEST_ATTR_ADD_NAME);
    fail_unless(strncmp((const char *) el->values[0].data,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    fail_unless(data != NULL, "talloc_zero failed");
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(test_ctx, const char *, 3);
    fail_unless(data->attrlist != NULL, "talloc_array failed");
    data->attrlist[0] = TEST_ATTR_NAME;
    data->attrlist[1] = TEST_ATTR_ADD_NAME;
    data->attrlist[2] = NULL;

    ret = sysdb_search_custom(data, data->ctx->domain, filter,
                              CUSTOM_TEST_CONTAINER,
                              data->attrlist,
                              &data->msgs_count,
                              &data->msgs);

    fail_if(ret != EOK, "Could not search custom object");

    fail_unless(data->msgs_count == 10,
                "Wrong number of objects, exptected [10] got [%d]",
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;

    ret = test_delete_custom(data);

    fail_if(ret != EOK, "Could not delete custom object");
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
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_cache_password(test_ctx->domain, data->username,
                               data->username);

    fail_unless(ret == EOK, "sysdb_cache_password request failed [%d].", ret);

    talloc_free(test_ctx);
}
END_TEST

static void cached_authentication_without_expiration(const char *username,
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
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = username;

    val[0] = "0";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    ret = sysdb_cache_auth(test_ctx->domain, data->username,
                           password, test_ctx->confdb, false,
                           &expire_date, &delayed_until);

    fail_unless(ret == expected_result, "sysdb_cache_auth request does not "
                                        "return expected result [%d].",
                                        expected_result);

    fail_unless(expire_date == 0, "Wrong expire date, expected [%d], got [%d]",
                                  0, expire_date);

    fail_unless(delayed_until == -1, "Wrong delay, expected [%d], got [%d]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

static void cached_authentication_with_expiration(const char *username,
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
    fail_unless(ret == EOK, "Could not set up the test");

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->username = username;

    val[0] = "1";
    ret = confdb_add_param(test_ctx->confdb, true, CONFDB_PAM_CONF_ENTRY,
                           CONFDB_PAM_CRED_TIMEOUT, val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return;
    }

    now = time(NULL);
    expected_expire_date = now + (24 * 60 * 60);
    DEBUG(SSSDBG_TRACE_ALL,
          "Setting SYSDB_LAST_ONLINE_AUTH to [%lld].\n", (long long) now);

    data->attrs = sysdb_new_attrs(data);
    ret = sysdb_attrs_add_time_t(data->attrs, SYSDB_LAST_ONLINE_AUTH, now);

    ret = sysdb_set_user_attr(data->ctx->domain, data->username, data->attrs,
                              SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Could not modify user %s", data->username);

    ret = sysdb_cache_auth(data->ctx->domain, data->username,
                           password, test_ctx->confdb, false,
                           &expire_date, &delayed_until);

    fail_unless(ret == expected_result,
                "sysdb_cache_auth request does not return expected "
                "result [%d], got [%d].", expected_result, ret);

    fail_unless(expire_date == expected_expire_date,
                "Wrong expire date, expected [%d], got [%d]",
                expected_expire_date, expire_date);

    fail_unless(delayed_until == -1, "Wrong delay, expected [%d], got [%d]",
                                  -1, delayed_until);

    talloc_free(test_ctx);
}

START_TEST (test_sysdb_cached_authentication_missing_password)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, "abc",
                                             ERR_NO_CACHED_CREDS);
    cached_authentication_with_expiration(username, "abc",
                                             ERR_NO_CACHED_CREDS);

    talloc_free(tmp_ctx);

}
END_TEST

START_TEST (test_sysdb_cached_authentication_wrong_password)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, "abc",
                                             ERR_AUTH_FAILED);
    cached_authentication_with_expiration(username, "abc",
                                             ERR_AUTH_FAILED);

    talloc_free(tmp_ctx);

}
END_TEST

START_TEST (test_sysdb_cached_authentication)
{
    TALLOC_CTX *tmp_ctx;
    char *username;

    tmp_ctx = talloc_new(NULL);
    fail_unless(tmp_ctx != NULL, "talloc_new failed.");

    username = talloc_asprintf(tmp_ctx, "testuser%d", _i);
    fail_unless(username != NULL, "talloc_asprintf failed.");

    cached_authentication_without_expiration(username, username, EOK);
    cached_authentication_with_expiration(username, username, EOK);

    talloc_free(tmp_ctx);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = ASQ_TEST_USER_UID;

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");

    data->attrlist[0] = "gidNumber";
    data->attrlist[1] = NULL;

    user_dn = sysdb_user_dn(data, data->ctx->domain, ASQ_TEST_USER);
    fail_unless(user_dn != NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(data, test_ctx->domain,
                           user_dn, NULL, "memberof",
                           data->attrlist, &msgs_count, &msgs);

    fail_if(ret != EOK, "Failed to send ASQ search request.\n");

    fail_unless(msgs_count == 10, "wrong number of results, "
                                  "found [%d] expected [10]", msgs_count);

    for (i = 0; i < msgs_count; i++) {
        fail_unless(msgs[i]->num_elements == 1, "wrong number of elements, "
                                     "found [%d] expected [1]",
                                     msgs[i]->num_elements);

        fail_unless(msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    msgs[i]->elements[0].num_values);

        gid_str = talloc_asprintf(data, "%d", 28010 + i);
        fail_unless(gid_str != NULL, "talloc_asprintf failed.");
        fail_unless(strncmp(gid_str,
                            (const char *) msgs[i]->elements[0].values[0].data,
                            msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            msgs[i]->elements[0].values[0].length,
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
    char *uid_str;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed");

    data->attrlist[0] = "uidNumber";
    data->attrlist[1] = NULL;

    ret = test_search_all_users(data);

    fail_if(ret != EOK, "Search failed");

    fail_unless(data->msgs_count == 10,
                "wrong number of results, found [%d] expected [10]",
                data->msgs_count);

    for (i = 0; i < data->msgs_count; i++) {
        fail_unless(data->msgs[i]->num_elements == 1,
                    "wrong number of elements, found [%d] expected [1]",
                    data->msgs[i]->num_elements);

        fail_unless(data->msgs[i]->elements[0].num_values == 1,
                    "wrong number of values, found [%d] expected [1]",
                    data->msgs[i]->elements[0].num_values);

        uid_str = talloc_asprintf(data, "%d", 27010 + i);
        fail_unless(uid_str != NULL, "talloc_asprintf failed.");
        fail_unless(strncmp(uid_str,
                            (char *) data->msgs[i]->elements[0].values[0].data,
                            data->msgs[i]->elements[0].values[0].length)  == 0,
                            "wrong value, found [%.*s] expected [%s]",
                            data->msgs[i]->elements[0].values[0].length,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;

    ret = test_delete_recursive(data);

    fail_if(ret != EOK, "Recursive delete failed");
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_attrs_replace_name)
{
    struct sysdb_attrs *attrs;
    struct ldb_message_element *el;
    int ret;

    attrs = sysdb_new_attrs(NULL);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, "foo", "bar");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "fool", "bool");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_add_string(attrs, "foot", "boot");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_replace_name(attrs, "foo", "foot");
    fail_unless(ret == EEXIST,
                "sysdb_attrs_replace overwrites existing attribute");

    ret = sysdb_attrs_replace_name(attrs, "foo", "oof");
    fail_unless(ret == EOK, "sysdb_attrs_replace failed");

    ret = sysdb_attrs_get_el(attrs, "foo", &el);
    fail_unless(ret == EOK, "sysdb_attrs_get_el failed");
    fail_unless(el->num_values == 0, "Attribute foo is not empty.");

    ret = sysdb_attrs_get_el(attrs, "oof", &el);
    fail_unless(ret == EOK, "sysdb_attrs_get_el failed");
    fail_unless(el->num_values == 1,
                "Wrong number of values for attribute oof, "
                "expected [1] got [%d].", el->num_values);
    fail_unless(strncmp("bar", (char *) el->values[0].data,
                        el->values[0].length) == 0,
                "Wrong value, expected [bar] got [%.*s]", el->values[0].length,
                                                          el->values[0].data);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = MBO_GROUP_BASE + _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        fail_unless(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
    }

    ret = test_memberof_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        fail_unless(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
    }

    data->memberlist = talloc_array(data, char *, 2);
    fail_unless(data->memberlist != NULL, "talloc_array failed.");
    data->memberlist[0] = talloc_asprintf(data, "testuser%d", data->gid);
    data->memberlist[1] = NULL;

    ret = test_memberof_store_group_with_ghosts(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    if (_i == 0) {
        data->attrlist = NULL;
    } else {
        data->attrlist = talloc_array(data, const char *, 2);
        fail_unless(data->attrlist != NULL, "talloc_array failed.");
        data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid - 1);
        data->attrlist[1] = NULL;
    }

    data->memberlist = talloc_array(data, char *, 3);
    fail_unless(data->memberlist != NULL, "talloc_array failed.");
    data->memberlist[0] = talloc_asprintf(data, "testusera%d", data->gid);
    data->memberlist[1] = talloc_asprintf(data, "testuserb%d", data->gid);
    data->memberlist[2] = NULL;

    ret = test_memberof_store_group_with_ghosts(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ghostname = talloc_asprintf(data, "testghost%d", _i);
    fail_unless(ghostname != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname);
    fail_unless(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the add, the groups should not contain the ghost attribute */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        if (data->gid > MBO_GROUP_BASE) {
            /* The first group would have the ghost attribute gone completely */
            fail_if(el == NULL, "Cannot find ghost element\n");
            test_gv = ldb_msg_find_val(el, &gv);
            fail_unless(test_gv == NULL,
                        "Ghost user %s unexpectedly found\n", ghostname);
        } else {
            fail_unless(el == NULL, "Stray values in ghost element?\n");
        }
    }

    /* Perform the add operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_ADD);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* Before the delete, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    /* The test replaces the testuser%i attribute with testghost%i */
    ghostname_del = talloc_asprintf(data, "testuser%d", _i);
    fail_unless(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = talloc_asprintf(data, "testghost%d", _i);
    fail_unless(ghostname_add != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    fail_unless(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_del);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);
    }

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, all groups with gid >= _i have the testghost%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_add;
        gv.length = strlen(ghostname_add);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = MBO_GROUP_BASE + 10 - _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    /* The test replaces the attributes (testusera$gid, testuserb$gid) with
     * just testusera$gid. The result should be not only testusera, but also
     * all ghost users inherited from child groups
     */
    ghostname_rep = talloc_asprintf(data, "testusera%d", data->gid);
    fail_unless(ghostname_rep != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_rep);
    fail_unless(ret == EOK, "Cannot add attr\n");

    ghostname_del = talloc_asprintf(data, "testuserb%d", data->gid);
    fail_unless(ghostname_del != NULL, "Out of memory\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, all groups with gid >= _i have both testuser a
     * and testuserb as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_rep;
        gv.length = strlen(ghostname_rep);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_rep);

        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_rep);

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

        /* inherited users must be there */
        for (iteruid = MBO_GROUP_BASE ; iteruid < itergid ; iteruid++) {
            ghostname_check = talloc_asprintf(data, "testusera%d", iteruid);
            gv.data = (uint8_t *) ghostname_check;
            gv.length = strlen(ghostname_check);

            test_gv = ldb_msg_find_val(el, &gv);
            fail_if(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                    ghostname_check);

            if (iteruid < data->gid) {
                /* Also check the B user if it hasn't been deleted yet */
                ghostname_check = talloc_asprintf(data, "testuserb%d", iteruid);
                gv.data = (uint8_t *) ghostname_check;
                gv.length = strlen(ghostname_check);

                test_gv = ldb_msg_find_val(el, &gv);
                fail_if(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                        ghostname_check);
            }
            talloc_zfree(ghostname_check);
        }
    }

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, testusera should still be there, but we also need
     * to keep ghost users inherited from other groups
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname_rep;
        gv.length = strlen(ghostname_rep);

        /* testusera must still be there */
        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_rep);

        /* testuserb must be gone */
        gv.data = (uint8_t *) ghostname_del;
        gv.length = strlen(ghostname_rep);

        test_gv = ldb_msg_find_val(el, &gv);
        fail_unless(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

        /* inherited users must still be there */
        for (iteruid = MBO_GROUP_BASE ; iteruid < itergid ; iteruid++) {
            ghostname_check = talloc_asprintf(data, "testusera%d", iteruid);
            gv.data = (uint8_t *) ghostname_check;
            gv.length = strlen(ghostname_check);

            test_gv = ldb_msg_find_val(el, &gv);
            fail_if(test_gv == NULL, "Cannot find inherited ghost user %s\n",
                    ghostname_check);

            if (iteruid < data->gid) {
                /* Also check the B user if it hasn't been deleted yet */
                ghostname_check = talloc_asprintf(data, "testuserb%d", iteruid);
                gv.data = (uint8_t *) ghostname_check;
                gv.length = strlen(ghostname_check);

                test_gv = ldb_msg_find_val(el, &gv);
                fail_if(test_gv == NULL, "Cannot find inherited ghost user %s\n",
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = MBO_GROUP_BASE;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = talloc_asprintf(data, "testgroup%d", data->gid + 9);
    data->attrlist[1] = NULL;

    ret = test_memberof_store_group(data);

    fail_if(ret != EOK, "Could not store POSIX group #%d", data->gid);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = MBO_USER_BASE + _i;
    data->gid = 0; /* MPG domain */
    data->username = talloc_asprintf(data, "testuser%d", data->uid);

    ret = test_store_user(data);

    fail_if(ret != EOK, "Could not store user %s", data->username);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i + MBO_GROUP_BASE);
    data->uid = MBO_USER_BASE + _i;

    ret = test_add_group_member(data);

    fail_if(ret != EOK, "Could not modify group %s", data->groupname);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    _i + MBO_GROUP_BASE, data->attrlist,
                                    &data->msg);
    if (_i == 5) {
        fail_unless(ret == ENOENT,
                    "sysdb_search_group_by_gid found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        fail_if(ret != EOK, "Could not check group %d", data->gid);
    } else {
        fail_if(ret != EOK, "Could not check group %d", data->gid);

        fail_unless(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        fail_unless(data->msg->elements[0].num_values == ((_i + 1) % 6),
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    _i + MBO_GROUP_BASE, data->attrlist,
                                    &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    fail_unless(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == _i + 1,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    _i + MBO_GROUP_BASE, data->attrlist,
                                    &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    fail_unless(data->msg->num_elements == 1,
                "Wrong number of results, expected [1] got [%d]",
                data->msg->num_elements);
    fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == 10,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i + MBO_GROUP_BASE;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "tallo_array failed.");
    data->attrlist[0] = "memberuid";
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain,
                                    _i + MBO_GROUP_BASE, data->attrlist,
                                    &data->msg);

    if (_i == 5) {
        fail_unless(ret == ENOENT,
                    "sysdb_search_group_by_gid_send found "
                    "already deleted group");
        if (ret == ENOENT) ret = EOK;

        fail_if(ret != EOK, "Could not check group %d", data->gid);
    } else {
        fail_if(ret != EOK, "Could not check group %d", data->gid);

        fail_unless(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d]",
                    data->msg->num_elements);
        fail_unless(strcmp(data->msg->elements[0].name, "memberuid") == 0,
                    "Wrong attribute name");
        fail_unless(data->msg->elements[0].num_values == ((_i + 5) % 10),
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    fail_unless(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == _i - MBO_GROUP_BASE + 1,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i + 1, data->msg->elements[0].num_values);

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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    fail_unless(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == (_i - MBO_GROUP_BASE + 1)*2,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    delgid = data->gid - 1;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    fail_unless(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");

    /* Expect our own and our parent's */
    fail_unless(data->msg->elements[0].num_values == 2,
                "Wrong number of attribute values, expected [%d] got [%d]",
                2, data->msg->elements[0].num_values);

    /* Remove the parent */
    ret = sysdb_delete_group(data->ctx->domain, NULL, delgid);
    fail_if(ret != EOK, "Cannot delete group %llu [%d]: %s\n",
            (unsigned long long) data->gid, ret, strerror(ret));

    talloc_free(data->msg);

    /* Check the parent again. The inherited ghost user should be gone. */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n", (unsigned long long) data->gid);

    fail_unless(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");

    /* Expect our own now only */
    fail_unless(data->msg->elements[0].num_values == 1,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    ghostname = talloc_asprintf(data, "testuser%d", _i);
    fail_unless(ghostname != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname);
    fail_unless(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the delete, all groups with gid >= _i have the testuser%_i
     * as a member
     */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        fail_if(el == NULL, "Cannot find ghost element\n");

        test_gv = ldb_msg_find_val(el, &gv);
        fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname);
    }

    /* Delete the attribute */
    ret = sysdb_set_group_attr(test_ctx->domain,
                               data->groupname, data->attrs, SYSDB_MOD_DEL);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* After the delete, we shouldn't be able to find the ghost attribute */
    for (itergid = data->gid ; itergid < MBO_GROUP_BASE + NUM_GHOSTS; itergid++) {
        ret = sysdb_search_group_by_gid(data, test_ctx->domain, itergid,
                                        data->attrlist, &data->msg);
        fail_if(ret != EOK, "Cannot retrieve group %llu\n",
                (unsigned long long) data->gid);

        gv.data = (uint8_t *) ghostname;
        gv.length = strlen(ghostname);

        el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
        if (itergid > data->gid) {
            /* The first group would have the ghost attribute gone completely */
            fail_if(el == NULL, "Cannot find ghost element\n");
            test_gv = ldb_msg_find_val(el, &gv);
            fail_unless(test_gv == NULL,
                        "Ghost user %s unexpectedly found\n", ghostname);
        } else {
            fail_unless(el == NULL, "Stray values in ghost element?\n");
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    if (_i > MBO_GROUP_BASE) {
        /* After the previous test, the first group (gid == MBO_GROUP_BASE)
         * has no ghost users. That's a legitimate test case we need to account
         * for now.
         */
        fail_unless(data->msg->num_elements == 1,
                    "Wrong number of results, expected [1] got [%d] for %d",
                    data->msg->num_elements, data->gid);
    }

    if (data->msg->num_elements == 0) {
        talloc_free(test_ctx);
        return;
    }

    fail_unless(strcmp(data->msg->elements[0].name, SYSDB_GHOST) == 0,
                "Wrong attribute name");
    fail_unless(data->msg->elements[0].num_values == _i - MBO_GROUP_BASE,
                "Wrong number of attribute values, expected [%d] got [%d]",
                _i + 1, data->msg->elements[0].num_values);

    for (j = MBO_GROUP_BASE; j < _i; j++) {
        expected = talloc_asprintf(data, "testghost%d", j);
        fail_if(expected == NULL, "OOM\n");
        fail_unless(strcmp(expected,
                           (const char *) data->msg->elements[0].values[j-MBO_GROUP_BASE].data) == 0);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i * 2;
    data->gid = _i * 2;
    data->username = talloc_asprintf(data, "testghost%d", _i);

    ret = test_store_user(data);
    fail_if(ret != EOK, "Cannot add user %s\n", data->username);
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

    /* Eplicitly disable enumeration during setup as converting the ghost
     * users into real ones work only when enumeration is disabled
     */
    ret = _setup_sysdb_tests(&test_ctx, false);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;

    data->attrlist = talloc_array(data, const char *, 3);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = SYSDB_MEMBER;
    data->attrlist[2] = NULL;

    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);

    fail_if(ret != EOK, "Could not check group %d", data->gid);

    fail_unless(data->msg->num_elements == (_i == MBO_GROUP_BASE) ? 0 : 1,
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

    fail_if(exp_mem != members->num_values,
            "Expected %d members, found %d\n", exp_mem, members->num_values);
    if (exp_gh) {
        fail_if(exp_gh != ghosts->num_values,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    /* The test replaces the testghost%i attribute with testuser%i */
    ghostname_del = talloc_asprintf(data, "testghost%d", _i - 1);
    fail_unless(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = talloc_asprintf(data, "testuser%d", _i - 1);
    fail_unless(ghostname_add != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    fail_unless(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_del;
    gv.length = strlen(ghostname_del);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    fail_if(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_add;
    gv.length = strlen(ghostname_add);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    fail_if(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->gid = _i;
    data->groupname = talloc_asprintf(data, "testgroup%d", data->gid);

    data->attrs = sysdb_new_attrs(data);
    if (ret != EOK) {
        fail("Could not create the changeset");
        return;
    }

    /* The test replaces the testghost%i attribute with testuser%i */
    ghostname_del = talloc_asprintf(data, "testuser%d", _i - 1);
    fail_unless(ghostname_del != NULL, "Out of memory\n");

    ghostname_add = talloc_asprintf(data, "testuser%d", _i - 1);
    fail_unless(ghostname_add != NULL, "Out of memory\n");
    ret = sysdb_attrs_steal_string(data->attrs, SYSDB_GHOST, ghostname_add);
    fail_unless(ret == EOK, "Cannot add attr\n");

    data->attrlist = talloc_array(data, const char *, 2);
    fail_unless(data->attrlist != NULL, "talloc_array failed.");
    data->attrlist[0] = SYSDB_GHOST;
    data->attrlist[1] = NULL;

    /* Before the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_del;
    gv.length = strlen(ghostname_del);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    fail_if(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_del);

    /* Perform the replace operation */
    ret =  sysdb_set_group_attr(test_ctx->domain,
                                data->groupname, data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Cannot set group attrs\n");

    /* After the replace, the group has the testghost%_i as a member */
    ret = sysdb_search_group_by_gid(data, test_ctx->domain, data->gid,
                                    data->attrlist, &data->msg);
    fail_if(ret != EOK, "Cannot retrieve group %llu\n",
            (unsigned long long) data->gid);

    gv.data = (uint8_t *) ghostname_add;
    gv.length = strlen(ghostname_add);

    el = ldb_msg_find_element(data->msg, SYSDB_GHOST);
    fail_if(el == NULL, "Cannot find ghost element\n");

    test_gv = ldb_msg_find_val(el, &gv);
    fail_if(test_gv == NULL, "Cannot find ghost user %s\n", ghostname_add);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i * 2;

    ret = test_remove_user_by_uid(data);

    fail_if(ret != EOK, "Could not remove user with uid %d", _i);
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
    fail_if(ret, "Add string failed");
    attrs_list[1] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[1], "test_attr", "attr2");
    fail_if(ret, "Add string failed");
    attrs_list[2] = sysdb_new_attrs(test_ctx);
    ret = sysdb_attrs_add_string(attrs_list[2], "nottest_attr", "attr3");
    fail_if(ret, "Add string failed");

    ret = sysdb_attrs_to_list(test_ctx, attrs_list, 3,
                              "test_attr", &list);
    fail_unless(ret == EOK, "sysdb_attrs_to_list failed with code %d", ret);

    fail_unless(strcmp(list[0],"attr1") == 0, "Expected [attr1], got [%s]",
                                              list[0]);
    fail_unless(strcmp(list[1],"attr2") == 0, "Expected [attr2], got [%s]",
                                              list[1]);
    fail_unless(list[2] == NULL, "List should be NULL-terminated");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_group_rename)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    gid_t gid;
    const gid_t grgid = 38001;
    const char *name;
    const char *fromname = "fromgroup";
    const char *toname = "togroup";
    struct ldb_result *res;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    /* Store and verify the first group */
    ret = sysdb_store_group(test_ctx->domain,
                            fromname, grgid, NULL, 0, 0);
    fail_unless(ret == EOK, "Could not add first group");

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, fromname, &res);
    fail_unless(ret == EOK, "Could not retrieve the group from cache\n");
    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    fail_unless(gid == grgid,
                "Did not find the expected GID (found %llu expected %llu)",
                (unsigned long long) gid, (unsigned long long) grgid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(fromname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Perform rename and check that GID is the same, but name changed */
    ret = sysdb_add_group(test_ctx->domain, toname, grgid, NULL, 0, 0);
    fail_unless(ret == EEXIST, "Group renamed with a low level call?");

    ret = sysdb_store_group(test_ctx->domain,
                            toname, grgid, NULL, 0, 0);
    fail_unless(ret == EOK, "Could not add first group");

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, toname, &res);
    fail_unless(ret == EOK, "Could not retrieve the group from cache\n");
    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
    fail_unless(gid == grgid,
                "Did not find the expected GID (found %llu expected %llu)",
                (unsigned long long) gid, (unsigned long long) grgid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(toname, name) == 0,
                "Did not find the expected GID (found %s expected %s)",
                name, toname);

    /* Verify the first name is gone */
    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, fromname, &res);
    fail_unless(ret == EOK, "Could not retrieve the group from cache\n");
    fail_unless(res->count == 0, "Unexpectedly found the original user\n");

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
    const char *fromname = "fromuser";
    const char *toname = "touser";
    struct ldb_result *res;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    /* Store and verify the first user */
    ret = sysdb_store_user(test_ctx->domain,
                           fromname, NULL, userid, 0,
                           fromname, "/", "/bin/sh",
                           NULL, NULL, NULL, 0, 0);
    fail_unless(ret == EOK, "Could not add first user");

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, fromname, &res);
    fail_unless(ret == EOK, "Could not retrieve the user from cache\n");
    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    fail_unless(uid == userid,
                "Did not find the expected UID (found %llu expected %llu)",
                (unsigned long long) uid, (unsigned long long) userid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(fromname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Perform rename and check that GID is the same, but name changed */
    ret = sysdb_add_user(test_ctx->domain, toname, userid, 0,
                         fromname, "/", "/bin/sh", NULL, NULL, 0, 0);
    fail_unless(ret == EEXIST, "A second user added with low level call?");

    ret = sysdb_store_user(test_ctx->domain, toname, NULL,
                           userid, 0, fromname, "/", "/bin/sh",
                           NULL, NULL, NULL, 0, 0);
    fail_unless(ret == EOK, "Could not add second user");

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, toname, &res);
    fail_unless(ret == EOK, "Could not retrieve the user from cache\n");
    if (res->count != 1) {
        fail("Invalid number of replies. Expected 1, got %d", res->count);
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
    fail_unless(uid == userid,
                "Did not find the expected UID (found %llu expected %llu)",
                (unsigned long long) uid, (unsigned long long) userid);
    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(toname, name) == 0,
                "Did not find the expected name (found %s expected %s)",
                name, fromname);

    /* Verify the first name is gone */
    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, fromname, &res);
    fail_unless(ret == EOK, "Could not retrieve the user from cache\n");
    fail_unless(res->count == 0, "Unexpectedly found the original user\n");

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
    errno_t ret;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_unless(ret == EOK, "Could not set up the test");

    /* Add a user to two groups */
    add_groups = talloc_array(test_ctx, char *, 3);
    add_groups[0] = talloc_strdup(add_groups, "testgroup28001");
    add_groups[1] = talloc_strdup(add_groups, "testgroup28002");
    add_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->domain, user, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups, NULL);
    fail_unless(ret == EOK, "Could not add groups");
    talloc_zfree(add_groups);

    /* Remove a user from one group and add to another */
    del_groups = talloc_array(test_ctx, char *, 2);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28001");
    del_groups[1] = NULL;
    add_groups = talloc_array(test_ctx, char *, 2);
    add_groups[0] = talloc_strdup(add_groups, "testgroup28003");
    add_groups[1] = NULL;

    ret = sysdb_update_members(test_ctx->domain, user, SYSDB_MEMBER_USER,
                               (const char *const *)add_groups,
                               (const char *const *)del_groups);
    fail_unless(ret == EOK, "Group replace failed");
    talloc_zfree(add_groups);
    talloc_zfree(del_groups);

    /* Remove a user from two groups */
    del_groups = talloc_array(test_ctx, char *, 3);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28002");
    del_groups[1] = talloc_strdup(del_groups, "testgroup28003");
    del_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->domain, user, SYSDB_MEMBER_USER,
                               NULL, (const char *const *)del_groups);
    fail_unless(ret == EOK, "Could not remove groups");

    talloc_zfree(test_ctx);
}
END_TEST


START_TEST (test_sysdb_group_dn_name)
{
    struct sysdb_test_ctx *test_ctx;
    int ret;
    struct ldb_dn *group_dn;
    const char *groupname;
    char *parsed;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    group_dn = sysdb_group_dn(test_ctx, test_ctx->domain, groupname);
    if (!group_dn || !groupname) {
        fail("Out of memory");
        return;
    }

    ret = sysdb_group_dn_name(test_ctx->sysdb, test_ctx,
                              ldb_dn_get_linearized(group_dn), &parsed);
    fail_if(ret != EOK, "Cannot get the group name from DN");

    fail_if(strcmp(groupname, parsed) != 0,
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_add_basic_netgroup(data);

    fail_if(ret != EOK, "Could not add netgroup %s", data->netgrname);
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
        fail("Could not set up the test");
        return;
    }

    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_search_netgroup_by_name(test_ctx, test_ctx->domain,
                                        netgrname, NULL, &msg);
    fail_if(ret != EOK, "Could not find netgroup with name %s", netgrname);

    netgroup_dn = sysdb_netgroup_dn(test_ctx, test_ctx->domain, netgrname);
    fail_if(netgroup_dn == NULL);
    fail_if(ldb_dn_compare(msg->dn, netgroup_dn) != 0, "Found wrong netgroup!\n");
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_entry(data);

    fail_if(ret != EOK, "Could not remove netgroup %s", data->netgrname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_remove_netgroup_by_name(data);

    fail_if(ret != EOK, "Could not remove netgroup with name %s", data->netgrname);
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
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->ev = test_ctx->ev;
    data->uid = _i;         /* This is kinda abuse of uid, though */
    data->netgrname = talloc_asprintf(data, "testnetgr%d", _i);

    ret = test_set_netgroup_attr(data);

    fail_if(ret != EOK, "Could not set netgroup attribute %s", data->netgrname);
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
        fail("Could not set up the test");
        return;
    }

    description = talloc_asprintf(test_ctx, "Sysdb Netgroup %d", _i);
    netgrname = talloc_asprintf(test_ctx, "testnetgr%d", _i);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->domain, netgrname,
                                  attrs, &res);

    fail_if(ret != EOK, "Could not get netgroup attributes");
    fail_if(res->count != 1,
            "Invalid number of entries, expected 1, got %d", res->count);

    attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_DESCRIPTION, 0);
    fail_if(strcmp(attrval, description),
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
    fail_if(ret != EOK, "Could not set up the test");

    base_dn = sysdb_netgroup_base_dn(test_ctx, test_ctx->domain);
    fail_if(base_dn == NULL, "Could not get netgroup base DN");

    strdn = ldb_dn_get_linearized(base_dn);
    fail_if(strdn == NULL, "Could not get string netgroup base DN");

    fail_if(strstr(strdn, SYSDB_NETGROUP_CONTAINER) != strdn,
            "Malformed netgroup baseDN");
}
END_TEST

START_TEST(test_odd_characters)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct ldb_message *msg;
    const struct ldb_val *val;
    const char odd_username[] = "*(odd)\\user,name";
    const char odd_username_orig_dn[] =
        "\\2a\\28odd\\29\\5cuser,name,cn=users,dc=example,dc=com";
    const char odd_groupname[] = "*(odd\\*)\\group,name";
    const char odd_netgroupname[] = "*(odd\\*)\\netgroup,name";
    const char *received_user;
    const char *received_group;
    static const char *user_attrs[] = SYSDB_PW_ATTRS;
    static const char *netgr_attrs[] = SYSDB_NETGR_ATTRS;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    /* ===== Groups ===== */

    /* Add */
    ret = sysdb_add_incomplete_group(test_ctx->domain,
                                     odd_groupname, 20000, NULL, NULL, true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     odd_groupname, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_group_by_name error [%d][%s]",
                            ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_getgrnam(test_ctx, test_ctx->domain, odd_groupname, &res);
    fail_unless(ret == EOK, "sysdb_getgrnam error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_group = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(received_group, odd_groupname) == 0,
                "Expected [%s], got [%s]",
                odd_groupname, received_group);
    talloc_free(res);


    /* ===== Users ===== */

    /* Add */
    ret = sysdb_add_basic_user(test_ctx->domain,
                               odd_username,
                               10000, 10000,
                               "","","");
    fail_unless(ret == EOK, "sysdb_add_basic_user error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_search_user_by_name(test_ctx,
                                    test_ctx->domain,
                                    odd_username, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_name error [%d][%s]",
                            ret, strerror(ret));
    val = ldb_dn_get_component_val(msg->dn, 0);
    fail_unless(strcmp((char *)val->data, odd_username)==0,
                "Expected [%s] got [%s]\n",
                odd_username, (char *)val->data);
    talloc_zfree(msg);

    /* Add to the group */
    ret = sysdb_add_group_member(test_ctx->domain,
                                 odd_groupname, odd_username,
                                 SYSDB_MEMBER_USER, false);
    fail_unless(ret == EOK, "sysdb_add_group_member error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_getpwnam(test_ctx, test_ctx->domain, odd_username, &res);
    fail_unless(ret == EOK, "sysdb_getpwnam error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    received_user = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
    fail_unless(strcmp(received_user, odd_username) == 0,
                "Expected [%s], got [%s]",
                odd_username, received_user);
    talloc_zfree(res);

    /* Attributes */
    ret = sysdb_get_user_attr(test_ctx, test_ctx->domain, odd_username,
                              user_attrs, &res);
    fail_unless(ret == EOK, "sysdb_get_user_attr error [%d][%s]",
                            ret, strerror(ret));
    talloc_free(res);

    /* Delete User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    fail_unless(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));

    /* Delete non existing User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    fail_unless(ret == ENOENT, "sysdb_delete_user error [%d][%s]",
                               ret, strerror(ret));

    /* Delete Group */
    ret = sysdb_delete_group(test_ctx->domain, odd_groupname, 20000);
    fail_unless(ret == EOK, "sysdb_delete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Add */
    ret = sysdb_add_user(test_ctx->domain,
                         odd_username,
                         10000, 0,
                         "","","",
                         odd_username_orig_dn,
                         NULL, 5400, 0);
    fail_unless(ret == EOK, "sysdb_add_user error [%d][%s]",
                            ret, strerror(ret));

    /* Delete User */
    ret = sysdb_delete_user(test_ctx->domain, odd_username, 10000);
    fail_unless(ret == EOK, "sysdb_delete_user error [%d][%s]",
                            ret, strerror(ret));

    /* ===== Netgroups ===== */
    /* Add */
    ret = sysdb_add_netgroup(test_ctx->domain,
                             odd_netgroupname, "No description",
                             NULL, NULL, 30, 0);
    fail_unless(ret == EOK, "sysdb_add_netgroup error [%d][%s]",
                            ret, strerror(ret));

    /* Retrieve */
    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, odd_netgroupname, &res);
    fail_unless(ret == EOK, "sysdb_getnetgr error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    talloc_zfree(res);

    ret = sysdb_get_netgroup_attr(test_ctx, test_ctx->domain,
                                  odd_netgroupname, netgr_attrs, &res);
    fail_unless(ret == EOK, "sysdb_get_netgroup_attr error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);
    talloc_zfree(res);

    /* ===== Arbitrary Entries ===== */

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sss_ldb_search)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_dn *group_dn, *nonexist_dn;
    struct ldb_result *res;
    const char groupname[] = "test_group";
    const char *received_group;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    check_leaks_push(test_ctx);

    group_dn = sysdb_group_dn(test_ctx, test_ctx->domain, groupname);
    fail_if(group_dn == NULL, "sysdb_group_dn failed");

    nonexist_dn = sysdb_group_dn(test_ctx, test_ctx->domain,
                                 "non-existing-group");
    fail_if(nonexist_dn == NULL, "sysdb_group_dn failed");

    /* Add */
    ret = sysdb_add_incomplete_group(test_ctx->domain,
                                     groupname, 20000, NULL, NULL, true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                ret, strerror(ret));

    /* Retrieve */

    /* Empty filter */
    ret = sss_ldb_search(test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                         LDB_SCOPE_BASE, NULL, NULL);

    fail_unless(ret == EOK, "sss_ldb_search error [%d][%s]",
                ret, strerror(ret));

    fail_unless(res->count == 1, "Received [%d] responses",
                                 res->count);

    received_group = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME,
                                                 NULL);
    fail_unless(strcmp(received_group, groupname) == 0,
                "Expected [%s], got [%s]", groupname, received_group);

    talloc_zfree(res);

    /* Non-empty filter */
    ret = sss_ldb_search(test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                         LDB_SCOPE_BASE, NULL, "objectClass=group");

    fail_unless(ret == EOK, "sss_ldb_search error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Filter yeilding no results */
    ret = sss_ldb_search(test_ctx->sysdb->ldb, test_ctx, &res, group_dn,
                         LDB_SCOPE_BASE, NULL,
                         "objectClass=nonExistingObjectClass");

    fail_unless(ret == ENOENT, "sss_ldb_search error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Non-existing dn */
    ret = sss_ldb_search(test_ctx->sysdb->ldb, test_ctx, &res, nonexist_dn,
                         LDB_SCOPE_BASE, NULL, NULL);

    fail_unless(ret == ENOENT, "sss_ldb_search error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    talloc_zfree(nonexist_dn);
    talloc_zfree(group_dn);
    fail_unless(check_leaks_pop(test_ctx) == true, "Memory leak");
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
        fail_if(ret != EOK, "sysdb_getservbyname error [%s]\n",
                             strerror(ret));
    } else {
        /* Look up the newly-added service by port */
        ret = sysdb_getservbyport(test_ctx, test_ctx->domain, port, NULL,
                                  &res);
        fail_if(ret != EOK, "sysdb_getservbyport error [%s]\n",
                             strerror(ret));
    }
    fail_if(res == NULL, "ENOMEM");
    fail_if(res->count != 1);

    /* Make sure the returned entry matches */
    msg = res->msgs[0];
    ret_name = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_if(ret_name == NULL);
    fail_unless(strcmp(ret_name, primary_name) == 0);

    ret_port = ldb_msg_find_attr_as_int(msg, SYSDB_SVC_PORT, 0);
    fail_if (ret_port != port);

    el = ldb_msg_find_element(msg, SYSDB_NAME_ALIAS);
    for (i = 0; i < el->num_values; i++) {
        matched = false;
        for (j = 0; aliases[j]; j++) {
            if (strcmp(aliases[j], (const char *)el->values[i].data) == 0) {
                matched = true;
            }
        }
        fail_if(!matched, "Unexpected value in LDB entry: [%s]",
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
        fail_if(!matched, "Unexpected value in LDB entry: [%s]",
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
    fail_if(ret != EOK, "Could not set up the test");

    primary_name = talloc_asprintf(test_ctx, "test_service");
    fail_if(primary_name == NULL);

    aliases = talloc_array(test_ctx, const char *, 3);
    fail_if(aliases == NULL);

    aliases[0] = talloc_asprintf(aliases, "test_service_alias1");
    fail_if(aliases[0] == NULL);

    aliases[1] = talloc_asprintf(aliases, "test_service_alias2");
    fail_if(aliases[1] == NULL);

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    fail_if(protocols == NULL);

    protocols[0] = talloc_asprintf(protocols, "tcp");
    fail_if(protocols[0] == NULL);

    protocols[1] = talloc_asprintf(protocols, "udp");
    fail_if(protocols[1] == NULL);

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    fail_if(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_svc_add(NULL, test_ctx->domain,
                        primary_name, port,
                        aliases, protocols,
                        NULL);
    fail_unless(ret == EOK, "sysdb_svc_add error [%s]\n", strerror(ret));

    /* Search by name and make sure the results match */
    services_check_match_name(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    /* Search by port and make sure the results match */
    services_check_match_port(test_ctx,
                              primary_name, port,
                              aliases, protocols);

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    fail_if(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by name)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_svc_delete(test_ctx->domain, primary_name, 0, NULL);
    fail_if(ret != EOK, "[%s]", strerror(ret));

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
    fail_if(ret != EOK, "Could not set up the test");

    aliases = talloc_array(test_ctx, const char *, 3);
    fail_if(aliases == NULL);

    aliases[0] = talloc_asprintf(aliases, "test_service_alias1");
    fail_if(aliases[0] == NULL);

    aliases[1] = talloc_asprintf(aliases, "test_service_alias2");
    fail_if(aliases[1] == NULL);

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    fail_if(protocols == NULL);

    protocols[0] = talloc_asprintf(protocols, "tcp");
    fail_if(protocols[0] == NULL);

    protocols[1] = talloc_asprintf(protocols, "udp");
    fail_if(protocols[1] == NULL);

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    fail_if(ret != EOK, "[%s]", strerror(ret));

    /* Store this group (which will add it) */
    ret = sysdb_store_service(test_ctx->domain,
                              primary_name, port,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    fail_if(ret != EOK, "[%s]", strerror(ret));

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
    fail_if (ret != EOK, "[%s]", strerror(ret));

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
    fail_if (ret != EOK, "[%s]", strerror(ret));

    /* Change the port number */
    ret = sysdb_store_service(test_ctx->domain,
                              primary_name, altport,
                              aliases, protocols,
                              NULL, NULL, 1, 1);
    fail_if (ret != EOK, "[%s]", strerror(ret));

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
    fail_if(ret != EOK, "[%s]", strerror(ret));

    /* Clean up after ourselves (and test deleting by port)
     *
     * We have to do this after the transaction, because LDB
     * doesn't like adding and deleting the same entry in a
     * single transaction.
     */
    ret = sysdb_svc_delete(test_ctx->domain, NULL, altport, NULL);
    fail_if(ret != EOK, "[%s]", strerror(ret));

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
    fail_if(ret != EOK, "Could not set up the test");

    aliases = talloc_array(test_ctx, const char *, 3);
    fail_if(aliases == NULL);

    aliases[0] = talloc_asprintf(aliases, "remove_alias_alias1");
    fail_if(aliases[0] == NULL);

    aliases[1] = talloc_asprintf(aliases, "remove_alias_alias2");
    fail_if(aliases[1] == NULL);

    aliases[2] = NULL;

    protocols = talloc_array(test_ctx, const char *, 3);
    fail_if(protocols == NULL);

    protocols[0] = talloc_asprintf(protocols, "tcp");
    fail_if(protocols[0] == NULL);

    protocols[1] = talloc_asprintf(protocols, "udp");
    fail_if(protocols[1] == NULL);

    protocols[2] = NULL;

    ret = sysdb_transaction_start(test_ctx->sysdb);
    fail_if(ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_svc_add(NULL, test_ctx->domain,
                        primary_name, port,
                        aliases, protocols,
                        NULL);
    fail_unless(ret == EOK, "sysdb_svc_add error [%s]\n", strerror(ret));

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
    fail_if (dn == NULL);

    ret = sysdb_svc_remove_alias(test_ctx->sysdb, dn, aliases[1]);
    fail_if (ret != EOK, "[%s]", strerror(ret));

    ret = sysdb_transaction_commit(test_ctx->sysdb);
    fail_if(ret != EOK);

    ret = sysdb_transaction_start(test_ctx->sysdb);
    fail_if(ret != EOK);

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
    fail_if(ret != EOK, "[%s]", strerror(ret));

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

    ret = sysdb_attrs_add_lc_name_alias(NULL, NULL);
    fail_unless(ret == EINVAL, "EINVAL not returned for NULL input");

    attrs = sysdb_new_attrs(NULL);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_lc_name_alias(attrs, LC_NAME_ALIAS_TEST_VAL);
    fail_unless(ret == EOK, "sysdb_attrs_add_lc_name_alias failed");

    ret = sysdb_attrs_get_string(attrs, SYSDB_NAME_ALIAS, &str);
    fail_unless(ret == EOK, "sysdb_attrs_get_string failed");
    fail_unless(strcmp(str, LC_NAME_ALIAS_CHECK_VAL) == 0,
                "Unexpected value, expected [%s], got [%s]",
                LC_NAME_ALIAS_CHECK_VAL, str);

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
    fail_unless(tmp_ctx != NULL, "talloc_new failed");

    attrs = sysdb_new_attrs(NULL);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, attrname, "val1");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");
    ret = sysdb_attrs_add_string(attrs, attrname, "val2");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed");

    ret = sysdb_attrs_get_el_ext(attrs, attrname, false, &el);
    fail_unless(ret == EOK, "sysdb_attrs_get_el_ext failed");

    list = sss_ldb_el_to_string_list(tmp_ctx, el);
    fail_if(list == NULL, ("sss_ldb_el_to_string_list failed\n"));

    ck_assert_str_eq(list[0], "val1");
    ck_assert_str_eq(list[1], "val2");
    fail_unless(list[2] == NULL, "Expected terminated list");

    talloc_free(list);

    ret = sysdb_attrs_get_string_array(attrs, attrname, tmp_ctx, &list);
    fail_unless(ret == EOK, "sysdb_attrs_get_string_array failed");

    /* This test relies on values keeping the same order. It is the case
     * with LDB, but if we ever switch from LDB, we need to amend the test
     */
    ck_assert_str_eq(list[0], "val1");
    ck_assert_str_eq(list[1], "val2");
    fail_unless(list[2] == NULL, "Expected terminated list");

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

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");
    check_leaks_push(test_ctx);

    /* Search user */
    ret = sysdb_search_user_by_name(test_ctx, test_ctx->domain,
                                    "nonexisting_user", NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_user_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_user_by_uid(test_ctx, test_ctx->domain,
                                   1234, NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_user_by_uid error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_user_by_sid_str(test_ctx, test_ctx->domain,
                                       "S-5-4-3-2-1", NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_user_by_sid_str failed with "
                               "[%d][%s].", ret, strerror(ret));

    /* Search group */
    ret = sysdb_search_group_by_name(test_ctx, test_ctx->domain,
                                     "nonexisting_group", NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_group_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_group_by_gid(test_ctx, test_ctx->domain,
                                    1234, NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_group_by_gid error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain,
                                        "S-5-4-3-2-1", NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_group_by_sid_str failed with "
                               "[%d][%s].", ret, strerror(ret));
    talloc_zfree(msg);

    /* Search netgroup */
    ret = sysdb_search_netgroup_by_name(test_ctx, test_ctx->domain,
                                        "nonexisting_netgroup", NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_netgroup_by_name error [%d][%s].",
                               ret, strerror(ret));
    talloc_zfree(msg);

    ret = sysdb_getnetgr(test_ctx, test_ctx->domain, "nonexisting_netgroup",
                         &res);
    fail_unless(ret == ENOENT, "sysdb_getnetgr error [%d][%s]",
                ret, strerror(ret));
    talloc_zfree(res);

    /* Search object */
    /* TODO: Should return ENOENT */
    ret = sysdb_search_object_by_sid(test_ctx, test_ctx->domain,
                                     "S-5-4-3-2-1", NULL, &res);
    fail_unless(ret == EOK, "sysdb_search_object_by_sid_str failed with "
                             "[%d][%s].", ret, strerror(ret));
    fail_unless(res->count == 0, "sysdb_search_object_by_sid_str should not "
                                 "return anything.");
    talloc_zfree(res);

    /* Search can return more results */
    ret = sysdb_search_users(test_ctx, test_ctx->domain,
                             "("SYSDB_SHELL"=/bin/nologin)", NULL,
                             &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_users failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_groups(test_ctx, test_ctx->domain,
                              "("SYSDB_GIDNUM"=1234)", NULL,
                              &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_groups failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_netgroups(test_ctx, test_ctx->domain,
                                 "("SYSDB_NAME"=nonexisting)", NULL,
                                 &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_netgroups failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    /* Search custom */
    ret = sysdb_search_custom(test_ctx, test_ctx->domain,
                              "(distinguishedName=nonexisting)",
                              CUSTOM_TEST_CONTAINER, NULL,
                              &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_custom failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_custom_by_name(test_ctx, test_ctx->domain,
                                     "nonexisting",
                                     CUSTOM_TEST_CONTAINER, NULL,
                                     &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_custom_by_name failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    /* General search */
    user_dn = sysdb_user_dn(test_ctx, test_ctx->domain, "nonexisting_user");
    fail_if(user_dn == NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(test_ctx, test_ctx->domain,
                           user_dn, NULL, "memberof", NULL,
                           &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_asq_search failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb,
                             user_dn, LDB_SCOPE_SUBTREE,
                             "objectClass=user", NULL,
                             &count, &msgs);
    fail_unless(ret == ENOENT, "sysdb_search_entry failed: %d, %s",
                               ret, strerror(ret));
    talloc_zfree(msgs);
    talloc_zfree(user_dn);

    /* sss_ldb_search */
    user_dn = sysdb_user_dn(test_ctx, test_ctx->domain, "nonexisting_user");
    fail_if(user_dn == NULL, "sysdb_user_dn failed");
    ret = sss_ldb_search(test_ctx->sysdb->ldb, test_ctx, &res, user_dn,
                         LDB_SCOPE_BASE, NULL, "objectClass=user");

    fail_unless(ret == ENOENT, "sss_ldb_search failed: %d, %s",
                               ret, strerror(ret));

    talloc_zfree(res);
    talloc_zfree(user_dn);

    /* TODO: test sysdb_search_selinux_config */

    fail_unless(check_leaks_pop(test_ctx) == true, "Memory leak");
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
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_has_enumerated(test_ctx->domain, &enumerated);
    fail_if(ret != EOK, "Error [%d][%s] checking enumeration",
                        ret, strerror(ret));

    fail_if(enumerated, "Enumeration should default to false");

    ret = sysdb_set_enumerated(test_ctx->domain, true);
    fail_if(ret != EOK, "Error [%d][%s] setting enumeration",
                        ret, strerror(ret));

    /* Recheck enumeration status */
    ret = sysdb_has_enumerated(test_ctx->domain, &enumerated);
    fail_if(ret != EOK, "Error [%d][%s] checking enumeration",
                        ret, strerror(ret));

    fail_unless(enumerated, "Enumeration should have been set to true");

    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_sysdb_original_dn_case_insensitive)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    const char *filter;
    struct ldb_dn *base_dn;
    const char *no_attrs[] = { NULL };
    struct ldb_message **msgs;
    size_t num_msgs;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_add_incomplete_group(test_ctx->domain,
                                     "case_sensitive_group1", 29000,
                                     "cn=case_sensitive_group1,cn=example,cn=com",
                                     NULL, true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_add_incomplete_group(test_ctx->domain,
                                     "case_sensitive_group2", 29001,
                                     "cn=CASE_SENSITIVE_GROUP1,cn=EXAMPLE,cn=COM",
                                     NULL, true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    /* Search by originalDN should yield 2 entries */
    filter = talloc_asprintf(test_ctx, "%s=%s", SYSDB_ORIG_DN,
                             "cn=case_sensitive_group1,cn=example,cn=com");
    fail_if(filter == NULL, "Cannot construct filter\n");

    base_dn = sysdb_domain_dn(test_ctx, test_ctx->domain);
    fail_if(base_dn == NULL, "Cannot construct basedn\n");

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb,
                             base_dn, LDB_SCOPE_SUBTREE, filter, no_attrs,
                             &num_msgs, &msgs);
    fail_unless(ret == EOK, "cache search error [%d][%s]",
                            ret, strerror(ret));
    fail_unless(num_msgs == 2, "Did not find the expected number of entries using "
                               "case insensitive originalDN search");
}
END_TEST

START_TEST(test_sysdb_search_sid_str)
{
    errno_t ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_message *msg;
    struct sysdb_attrs *attrs = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_add_incomplete_group(test_ctx->domain,
                                     "group", 29000,
                                     "cn=group,cn=example,cn=com",
                                     "S-1-2-3-4", true, 0);
    fail_unless(ret == EOK, "sysdb_add_incomplete_group error [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain,
                                        "S-1-2-3-4", NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_group_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    /* Delete the group by SID */
    ret = sysdb_delete_by_sid(test_ctx->sysdb, test_ctx->domain, "S-1-2-3-4");
    fail_unless(ret == EOK, "sysdb_delete_by_sid failed with [%d][%s].",
                ret, strerror(ret));

    /* Verify it's gone */
    ret = sysdb_search_group_by_sid_str(test_ctx, test_ctx->domain, "S-1-2-3-4",
                                        NULL, &msg);
    fail_unless(ret == ENOENT, "sysdb_search_group_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    talloc_free(msg);
    msg = NULL;

    attrs = sysdb_new_attrs(test_ctx);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, "S-1-2-3-4-5");
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_add_user(test_ctx->domain, "SIDuser",
                         12345, 0, "SID user", "/home/siduser", "/bin/bash",
                         NULL, attrs, 0, 0);
    fail_unless(ret == EOK, "sysdb_add_user failed with [%d][%s].",
                ret, strerror(ret));

    ret = sysdb_search_user_by_sid_str(test_ctx, test_ctx->domain,
                                       "S-1-2-3-4-5", NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_sid_str failed with [%d][%s].",
                ret, strerror(ret));

    talloc_free(test_ctx);
}
END_TEST


START_TEST(test_sysdb_subdomain_create)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    const char *const dom1[4] = { "dom1.sub", "DOM1.SUB", "dom1", "S-1" };
    const char *const dom2[4] = { "dom2.sub", "DOM2.SUB", "dom2", "S-2" };

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                dom1[0], dom1[1], dom1[2], dom1[3],
                                false, false, NULL);
    fail_if(ret != EOK, "Could not set up the test (dom1)");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    fail_if(test_ctx->domain->subdomains == NULL, "Empyt sub-domain list.");
    fail_if(strcmp(test_ctx->domain->subdomains->name, dom1[0]) != 0,
            "Unexpected sub-domain found, expected [%s], got [%s]",
            dom1[0], test_ctx->domain->subdomains->name);

    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                dom2[0], dom2[1], dom2[2], dom2[3],
                                false, false, NULL);
    fail_if(ret != EOK, "Could not set up the test (dom2)");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    fail_if(test_ctx->domain->subdomains->next == NULL, "Missing sub-domain");
    fail_if(strcmp(test_ctx->domain->subdomains->next->name, dom2[0]) != 0,
            "Unexpected sub-domain found, expected [%s], got [%s]",
            dom2[0], test_ctx->domain->subdomains->next->name);

    ret = sysdb_subdomain_delete(test_ctx->sysdb, dom2[0]);
    fail_if(ret != EOK, "Could not delete subdomain");

    ret = sysdb_subdomain_delete(test_ctx->sysdb, dom1[0]);
    fail_if(ret != EOK, "Could not delete subdomain");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    fail_unless(test_ctx->domain->subdomains->disabled, "Subdomain not disabled.");
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
    struct sysdb_attrs *user_attrs;
    struct ldb_message *msg;

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[3],
                              false, false, NULL);
    fail_unless(subdomain != NULL, "Failed to create new subdomin.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[3],
                                false, false, NULL);
    fail_if(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    user_attrs = sysdb_new_attrs(test_ctx);
    fail_unless(user_attrs != NULL, "sysdb_new_attrs failed");

    ret = sysdb_attrs_add_string(user_attrs, SYSDB_NAME_ALIAS, "subdomuser");
    fail_unless(ret == EOK, "sysdb_store_user failed.");

    ret = sysdb_store_user(subdomain, "SubDomUser",
                           NULL, 12345, 0, "Sub Domain User",
                           "/home/subdomuser", "/bin/bash",
                           NULL, user_attrs, NULL, -1, 0);
    fail_unless(ret == EOK, "sysdb_store_user failed.");

    base_dn =ldb_dn_new(test_ctx, test_ctx->sysdb->ldb, "cn=sysdb");
    fail_unless(base_dn != NULL);

    check_dn = ldb_dn_new(test_ctx, test_ctx->sysdb->ldb,
                          "name=SubDomUser,cn=users,cn=test.sub,cn=sysdb");
    fail_unless(check_dn != NULL);

    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=SubDomUser");
    fail_unless(ret == EOK, "ldb_search failed.");
    fail_unless(results->count == 1, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     1, results->count);
    fail_unless(ldb_dn_compare(results->msgs[0]->dn, check_dn) == 0,
                "Unexpedted DN returned");

    /* Subdomains are case-insensitive. Test that the lowercased name
     * can be found, too */
    ret = sysdb_search_user_by_name(test_ctx, subdomain, "subdomuser", attrs,
                                    &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_name failed.");

    ret = sysdb_delete_user(subdomain, "subdomuser", 0);
    fail_unless(ret == EOK, "sysdb_delete_user failed [%d][%s].",
                            ret, strerror(ret));

    ret = ldb_search(test_ctx->sysdb->ldb, test_ctx, &results, base_dn,
                     LDB_SCOPE_SUBTREE, NULL, "name=subdomuser");
    fail_unless(ret == EOK, "ldb_search failed.");
    fail_unless(results->count == 0, "Unexpected number of results, "
                                     "expected [%d], got [%d]",
                                     0, results->count);
}
END_TEST

START_TEST(test_sysdb_subdomain_user_ops)
{
    struct sysdb_test_ctx *test_ctx;
    errno_t ret;
    struct sss_domain_info *subdomain = NULL;
    struct ldb_message *msg = NULL;
    struct ldb_dn *check_dn = NULL;

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[3],
                              false, false, NULL);
    fail_unless(subdomain != NULL, "Failed to create new subdomin.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[3],
                                false, false, NULL);
    fail_if(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_store_user(subdomain, "subdomuser",
                           NULL, 12345, 0, "Sub Domain User",
                           "/home/subdomuser", "/bin/bash",
                           NULL, NULL, NULL, -1, 0);
    fail_unless(ret == EOK, "sysdb_store_domuser failed.");

    check_dn = ldb_dn_new(test_ctx, test_ctx->sysdb->ldb,
                          "name=subdomuser,cn=users,cn=test.sub,cn=sysdb");
    fail_unless(check_dn != NULL);

    ret = sysdb_search_user_by_name(test_ctx, subdomain, "subdomuser", NULL,
                                    &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_name failed with [%d][%s].",
                            ret, strerror(ret));
    fail_unless(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpedted DN returned");

    ret = sysdb_search_user_by_uid(test_ctx, subdomain, 12345, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_domuser_by_uid failed with [%d][%s].",
                            ret, strerror(ret));
    fail_unless(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpedted DN returned");

    ret = sysdb_delete_user(subdomain, "subdomuser", 12345);
    fail_unless(ret == EOK, "sysdb_delete_domuser failed with [%d][%s].",
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

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    subdomain = new_subdomain(test_ctx, test_ctx->domain,
                              testdom[0], testdom[1], testdom[2], testdom[3],
                              false, false, NULL);
    fail_unless(subdomain != NULL, "Failed to create new subdomin.");
    ret = sysdb_subdomain_store(test_ctx->sysdb,
                                testdom[0], testdom[1], testdom[2], testdom[3],
                                false, false, NULL);
    fail_if(ret != EOK, "Could not set up the test (test subdom)");

    ret = sysdb_update_subdomains(test_ctx->domain);
    fail_unless(ret == EOK, "sysdb_update_subdomains failed with [%d][%s]",
                            ret, strerror(ret));

    ret = sysdb_store_group(subdomain,
                            "subdomgroup", 12345, NULL, -1, 0);
    fail_unless(ret == EOK, "sysdb_store_domgroup failed.");

    check_dn = ldb_dn_new(test_ctx, test_ctx->sysdb->ldb,
                          "name=subdomgroup,cn=groups,cn=test.sub,cn=sysdb");
    fail_unless(check_dn != NULL);

    ret = sysdb_search_group_by_name(test_ctx, subdomain, "subdomgroup", NULL,
                                     &msg);
    fail_unless(ret == EOK, "sysdb_search_domgroup_by_name failed with [%d][%s].",
                            ret, strerror(ret));
    fail_unless(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpedted DN returned");

    ret = sysdb_search_group_by_gid(test_ctx, subdomain, 12345, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_domgroup_by_gid failed with [%d][%s].",
                            ret, strerror(ret));
    fail_unless(ldb_dn_compare(msg->dn, check_dn) == 0,
                "Unexpedted DN returned");

    ret = sysdb_delete_group(subdomain, "subdomgroup", 12345);
    fail_unless(ret == EOK, "sysdb_delete_domgroup failed with [%d][%s].",
                            ret, strerror(ret));

}
END_TEST

#ifdef BUILD_AUTOFS
START_TEST(test_autofs_create_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_save_autofsmap(test_ctx->domain, autofsmapname,
                               autofsmapname, NULL, 0, 0);
    fail_if(ret != EOK, "Could not store autofs map %s", autofsmapname);
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
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_get_map_byname(test_ctx, test_ctx->domain,
                               autofsmapname, &map);
    fail_if(ret != EOK, "Could not retrieve autofs map %s", autofsmapname);
    fail_if(map == NULL, "No map retrieved?\n");
    talloc_free(test_ctx);
}
END_TEST

START_TEST(test_autofs_delete_map)
{
    struct sysdb_test_ctx *test_ctx;
    const char *autofsmapname;
    errno_t ret;

    ret = setup_sysdb_tests(&test_ctx);
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_delete_autofsmap(test_ctx->domain, autofsmapname);
    fail_if(ret != EOK, "Could not retrieve autofs map %s", autofsmapname);
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
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_get_map_byname(test_ctx, test_ctx->domain,
                               autofsmapname, &map);
    fail_if(ret != ENOENT, "Expected ENOENT, got %d instead\n", ret);
    fail_if(map != NULL, "Unexpected map found\n");
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
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    for (ii=0; ii < limit; ii++) {
        autofskey = talloc_asprintf(test_ctx, "%s_testkey%d",
                                    autofsmapname, ii);
        fail_if(autofskey == NULL, "Out of memory\n");

        autofsval = talloc_asprintf(test_ctx, "testserver:/testval%d", ii);
        fail_if(autofsval == NULL, "Out of memory\n");

        ret = sysdb_save_autofsentry(test_ctx->domain,
                                     autofsmapname, autofskey,
                                     autofsval, NULL);
        fail_if(ret != EOK, "Could not save autofs entry %s", autofskey);
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
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    ret = sysdb_autofs_entries_by_map(test_ctx, test_ctx->domain,
                                      autofsmapname, &count, &entries);
    fail_if(ret != EOK, "Cannot get autofs entries for map %s\n",
            autofsmapname);
    fail_if(count != expected, "Expected to find %d entries, got %d\n",
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
    fail_if(ret != EOK, "Could not set up the test");

    autofsmapname = talloc_asprintf(test_ctx, "testmap%d", _i);
    fail_if(autofsmapname == NULL, "Out of memory\n");

    autofskey = talloc_asprintf(test_ctx, "testkey");
    fail_if(autofskey == NULL, "Out of memory\n");

    autofsval = talloc_asprintf(test_ctx, "testserver:/testval%d", _i);
    fail_if(autofsval == NULL, "Out of memory\n");

    ret = sysdb_save_autofsentry(test_ctx->domain,
                                 autofsmapname, autofskey,
                                 autofsval, NULL);
    fail_if(ret != EOK, "Could not save autofs entry %s", autofskey);
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
    fail_if(ret != EOK, "Could not set up the test");

    autofskey = talloc_asprintf(test_ctx, "testkey");
    fail_if(autofskey == NULL, "Out of memory\n");

    filter = talloc_asprintf(test_ctx, "(&(objectclass=%s)(%s=%s))",
                             SYSDB_AUTOFS_ENTRY_OC, SYSDB_AUTOFS_ENTRY_KEY, autofskey);
    fail_if(filter == NULL, "Out of memory\n");

    dn = ldb_dn_new_fmt(test_ctx, test_ctx->sysdb->ldb, SYSDB_TMPL_CUSTOM_SUBTREE,
                        AUTOFS_MAP_SUBDIR, test_ctx->domain->name);
    fail_if(dn == NULL, "Out of memory\n");

    ret = sysdb_search_entry(test_ctx, test_ctx->sysdb, dn, LDB_SCOPE_SUBTREE,
                             filter, attrs, &count, &msgs);
    fail_if(count != expected, "Found %d entries with name %s, expected %d\n",
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
        fail("Could not create %s directory", TESTS_PATH);
        return NULL;
    }

    conf_db = talloc_asprintf(mem_ctx, "%s/%s", TESTS_PATH, TEST_CONF_FILE);
    ck_assert(conf_db != NULL);

    /* Make sure the test domain does not interfere with our testing */
    ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
    if (ret != EOK && errno != ENOENT) {
        fail("Could not remove confdb %s\n", TESTS_PATH"/"TEST_CONF_FILE);
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
    val[0] = "LOCAL";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    ck_assert_int_eq(ret, EOK);
    ck_assert(names != NULL);
    ck_assert_str_eq(names[0], "LOCAL");
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
        fail("Could not set up the test");
        return;
    }

    attrs = sysdb_new_attrs(test_ctx);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed.\n");

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, UPN_PRINC);
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_attrs_add_string(attrs, SYSDB_CANONICAL_UPN, UPN_CANON_PRINC);
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_user(test_ctx->domain,
                           UPN_USER_NAME, "x",
                           12345, 0, "UPN USER", "/home/upn_user",
                           "/bin/bash", NULL,
                           attrs, NULL, -1, 0);
    fail_unless(ret == EOK, "Could not store user.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   "abc@def.ghi", NULL, &msg);
    fail_unless(ret == ENOENT,
                "sysdb_search_user_by_upn failed with non-existing UPN.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_PRINC, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

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
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_PRINC_WRONG_CASE, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_PRINC) == 0,
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
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_CANON_PRINC, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_CANON_PRINC) == 0,
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
        fail("Could not set up the test");
        return;
    }

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_CANON_PRINC_WRONG_CASE, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_CANON_PRINC) == 0,
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
        fail("Could not set up the test");
        return;
    }

    attrs = sysdb_new_attrs(test_ctx);
    fail_unless(attrs != NULL, "sysdb_new_attrs failed.\n");

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, UPN_CANON_PRINC);
    fail_unless(ret == EOK, "sysdb_attrs_add_string failed.");

    ret = sysdb_store_user(test_ctx->domain,
                           UPN_USER_NAME"_dup", "x",
                           23456, 0, "UPN USER DUP", "/home/upn_user_dup",
                           "/bin/bash", NULL,
                           attrs, NULL, -1, 0);
    fail_unless(ret == EOK, "Could not store user.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_CANON_PRINC, NULL, &msg);
    fail_unless(ret == EINVAL,
                "sysdb_search_user_by_upn failed for duplicated UPN.");

    ret = sysdb_search_user_by_upn(test_ctx, test_ctx->domain,
                                   UPN_PRINC, NULL, &msg);
    fail_unless(ret == EOK, "sysdb_search_user_by_upn failed.");

    str = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_USER_NAME) == 0, "Expected [%s], got [%s].",
                                                 UPN_USER_NAME, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_PRINC, str);

    str = ldb_msg_find_attr_as_string(msg, SYSDB_CANONICAL_UPN, NULL);
    fail_unless(str != NULL, "ldb_msg_find_attr_as_string failed.");
    fail_unless(strcmp(str, UPN_CANON_PRINC) == 0,
                "Expected [%s], got [%s].", UPN_CANON_PRINC, str);

    talloc_free(test_ctx);
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
    val[0] = "LOCAL";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(confdb, true,
                           "config/domain/LOCAL", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "REMOTE";
    ret = confdb_add_param(confdb, true,
                           "config/sssd", "domains", val);
    ck_assert_int_eq(ret, EOK);

    val[0] = "local";
    ret = confdb_add_param(confdb, true,
                           "config/domain/REMOTE", "id_provider", val);
    ck_assert_int_eq(ret, EOK);

    ret = confdb_list_all_domain_names(tmp_ctx, confdb, &names);
    ck_assert_int_eq(ret, EOK);
    ck_assert(names != NULL);
    ck_assert_str_eq(names[0], "LOCAL");
    ck_assert_str_eq(names[1], "REMOTE");
    ck_assert(names[2] == NULL);
    talloc_free(tmp_ctx);
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* test getting next id works */
    tcase_add_test(tc_sysdb, test_sysdb_get_new_id);

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_user,27000,27010);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27000, 27010);

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
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 28000, 28010);

    /* Remove the other half by uid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user_by_uid, 27000, 27010);

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

    /* Create incomplete groups - remove will fail if the LDB objects don't exist */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_incomplete_group, 28000, 28010);
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 28000, 28010);

    /* test custom operations */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_custom, 29010, 29020);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_by_name);
    tcase_add_test(tc_sysdb, test_sysdb_update_custom);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom_update);
    tcase_add_test(tc_sysdb, test_sysdb_search_custom);
    tcase_add_test(tc_sysdb, test_sysdb_delete_custom);

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

    /* Test SID string searches */
    tcase_add_test(tc_sysdb, test_sysdb_search_sid_str);

    /* Test user and group renames */
    tcase_add_test(tc_sysdb, test_group_rename);
    tcase_add_test(tc_sysdb, test_user_rename);

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

/* ===== SERVICE TESTS ===== */

    /* Create a new service */
    tcase_add_test(tc_sysdb, test_sysdb_add_services);
    tcase_add_test(tc_sysdb, test_sysdb_store_services);
    tcase_add_test(tc_sysdb, test_sysdb_svc_remove_alias);

    tcase_add_test(tc_sysdb, test_sysdb_attrs_add_lc_name_alias);

/* ===== UTIL TESTS ===== */
    tcase_add_test(tc_sysdb, test_sysdb_attrs_get_string_array);

/* ===== Test search return empty result ===== */
    tcase_add_test(tc_sysdb, test_sysdb_search_return_ENOENT);

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
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

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
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

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

    /* sss_ldb_search */
    tcase_add_test(tc_sysdb, test_sss_ldb_search);

    /* This loop counts backwards so the indexing is a little odd */
    tcase_add_loop_test(tc_memberof, test_sysdb_memberof_mod_replace_keep,
                        1 , 11);
    tcase_add_loop_test(tc_memberof, test_sysdb_remove_local_group_by_gid,
                        MBO_GROUP_BASE , MBO_GROUP_BASE + 10);

    suite_add_tcase(s, tc_memberof);

    TCase *tc_subdomain = tcase_create("SYSDB sub-domain Tests");

    tcase_add_test(tc_subdomain, test_sysdb_subdomain_create);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_store_user);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_user_ops);
    tcase_add_test(tc_subdomain, test_sysdb_subdomain_group_ops);

    suite_add_tcase(s, tc_subdomain);

#ifdef BUILD_AUTOFS
    TCase *tc_autofs = tcase_create("SYSDB autofs Tests");

    tcase_add_loop_test(tc_subdomain, test_autofs_create_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_retrieve_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_store_entry_in_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_retrieve_keys_by_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_delete_map,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_retrieve_map_neg,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_loop_test(tc_subdomain, test_autofs_key_duplicate,
                        TEST_AUTOFS_MAP_BASE, TEST_AUTOFS_MAP_BASE+10);

    tcase_add_test(tc_subdomain, test_autofs_get_duplicate_keys);

    suite_add_tcase(s, tc_autofs);
#endif

    TCase *tc_upn = tcase_create("SYSDB UPN tests");
    tcase_add_test(tc_upn, test_upn_basic);
    tcase_add_test(tc_upn, test_upn_basic_case);
    tcase_add_test(tc_upn, test_upn_canon);
    tcase_add_test(tc_upn, test_upn_canon_case);
    tcase_add_test(tc_upn, test_upn_dup);

    suite_add_tcase(s, tc_upn);

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

    if (!ldb_modules_path_is_set()) {
        fprintf(stderr, "Warning: LDB_MODULES_PATH is not set, "
                "will use LDB plugins installed in system paths.\n");
    }

    tests_set_cwd();

    test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, LOCAL_SYSDB_FILE);

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (failure_count == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_FILE, LOCAL_SYSDB_FILE);
    }
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
