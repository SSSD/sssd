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

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domain;
};

static int setup_sysdb_tests(struct sysdb_test_ctx **ctx)
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
    DEBUG(3, ("CONFDB: %s\n", conf_db));

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

    val[0] = "TRUE";
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

    ret = confdb_get_domain(test_ctx->confdb, "local", &test_ctx->domain);
    if (ret != EOK) {
        fail("Could not retrieve LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sysdb_domain_init(test_ctx,
                            test_ctx->domain, TESTS_PATH, &test_ctx->sysdb);
    if (ret != EOK) {
        fail("Could not initialize connection to the sysdb (%d)", ret);
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

struct test_data {
    struct tevent_context *ev;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    uid_t uid;
    gid_t gid;
    const char *shell;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char **attrlist;
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

    ret = sysdb_add_user(data, data->ctx->sysdb,
                         data->ctx->domain, data->username,
                         data->uid, 0, gecos, homedir, "/bin/bash",
                         NULL, 0);
    return ret;
}

static int test_store_user(struct test_data *data)
{
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    ret = sysdb_store_user(data, data->ctx->sysdb,
                           data->ctx->domain, data->username, "x",
                           data->uid, 0, gecos, homedir,
                           data->shell ? data->shell : "/bin/bash",
                           NULL, -1);
    return ret;
}

static int test_remove_user(struct test_data *data)
{
    struct ldb_dn *user_dn;
    int ret;

    user_dn = sysdb_user_dn(data->ctx->sysdb, data, "LOCAL", data->username);
    if (!user_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, user_dn, true);
    return ret;
}

static int test_remove_user_by_uid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data, data->ctx->sysdb,
                            data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_group(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data, data->ctx->sysdb,
                             data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_remove_nonexistent_user(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_user(data, data->ctx->sysdb,
                            data->ctx->domain, NULL, data->uid);
    return ret;
}

static int test_add_group(struct test_data *data)
{
    int ret;

    ret = sysdb_add_group(data, data->ctx->sysdb,
                          data->ctx->domain, data->groupname,
                          data->gid, NULL, 0);
    return ret;
}

static int test_store_group(struct test_data *data)
{
    int ret;

    ret = sysdb_store_group(data, data->ctx->sysdb,
                            data->ctx->domain, data->groupname,
                            data->gid, NULL, -1);
    return ret;
}

static int test_remove_group(struct test_data *data)
{
    struct ldb_dn *group_dn;
    int ret;

    group_dn = sysdb_group_dn(data->ctx->sysdb, data, "LOCAL", data->groupname);
    if (!group_dn) return ENOMEM;

    ret = sysdb_delete_entry(data->ctx->sysdb, group_dn, true);
    return ret;
}

static int test_remove_group_by_gid(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_group(data, data->ctx->sysdb,
                             data->ctx->domain, NULL, data->gid);
    if (ret == ENOENT) {
        ret = EOK;
    }
    return ret;
}

static int test_set_user_attr(struct test_data *data)
{
    int ret;

    ret = sysdb_set_user_attr(data, data->ctx->sysdb,
                              data->ctx->domain, data->username,
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

    ret = sysdb_add_group_member(data, data->ctx->sysdb,
                                 data->ctx->domain,
                                 data->groupname, username);
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

    ret = sysdb_remove_group_member(data, data->ctx->sysdb,
                                    data->ctx->domain,
                                    data->groupname, username);
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

    ret = sysdb_store_custom(data, data->ctx->sysdb,
                             data->ctx->domain, object_name,
                             CUSTOM_TEST_CONTAINER, data->attrs);
    return ret;
}

static int test_delete_custom(struct test_data *data)
{
    int ret;

    ret = sysdb_delete_custom(data, data->ctx->sysdb, data->ctx->domain,
                              CUSTOM_TEST_OBJECT, CUSTOM_TEST_CONTAINER);
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

    ret = sysdb_delete_recursive(data, data->ctx->sysdb, dn, false);
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

    ret = sysdb_store_group(data, data->ctx->sysdb,
                            data->ctx->domain, data->groupname,
                            data->gid, attrs, -1);
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
                         test_ctx->sysdb,
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
                         test_ctx->sysdb,
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
                         test_ctx->sysdb,
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
                         test_ctx->sysdb,
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
                         test_ctx->sysdb,
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
                         test_ctx->sysdb,
                         test_ctx->domain,
                         _i, &res);
    if (ret) {
        fail("sysdb_getpwuid failed for uid %d (%d: %s)",
             _i, ret, strerror(ret));
        goto done;
    }

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
                          test_ctx->sysdb,
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
                          test_ctx->sysdb,
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

    ret = sysdb_get_user_attr(test_ctx, test_ctx->sysdb,
                              test_ctx->domain, username,
                              attrs, &res);
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

    ret = sysdb_search_custom_by_name(data, data->ctx->sysdb,
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

    ret = sysdb_search_custom_by_name(data, data->ctx->sysdb,
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

    ret = sysdb_search_custom(data, data->ctx->sysdb,
                              data->ctx->domain,
                              filter,
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

    ret = sysdb_cache_password(data, test_ctx->sysdb,
                               test_ctx->domain, data->username,
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

    ret = sysdb_cache_auth(data, test_ctx->sysdb,
                           test_ctx->domain, data->username,
                           (const uint8_t *)password, strlen(password),
                           test_ctx->confdb, false, &expire_date, &delayed_until);

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
    DEBUG(9, ("Setting SYSDB_LAST_ONLINE_AUTH to [%lld].\n", (long long) now));

    data->attrs = sysdb_new_attrs(data);
    ret = sysdb_attrs_add_time_t(data->attrs, SYSDB_LAST_ONLINE_AUTH, now);

    ret = sysdb_set_user_attr(data, data->ctx->sysdb,
                              data->ctx->domain, data->username,
                              data->attrs, SYSDB_MOD_REP);
    fail_unless(ret == EOK, "Could not modify user %s", data->username);

    ret = sysdb_cache_auth(data, test_ctx->sysdb,
                           test_ctx->domain, data->username,
                           (const uint8_t *) password, strlen(password),
                           test_ctx->confdb, false, &expire_date, &delayed_until);

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

    cached_authentication_without_expiration(username, "abc", ENOENT);
    cached_authentication_with_expiration(username, "abc", ENOENT);

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

    cached_authentication_without_expiration(username, "abc", EINVAL);
    cached_authentication_with_expiration(username, "abc", EINVAL);

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

    user_dn = sysdb_user_dn(data->ctx->sysdb, data, "LOCAL", ASQ_TEST_USER);
    fail_unless(user_dn != NULL, "sysdb_user_dn failed");

    ret = sysdb_asq_search(data, test_ctx->sysdb,
                           test_ctx->domain, user_dn, NULL, "memberof",
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

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    data->ctx->domain, _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);
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

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    data->ctx->domain, _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

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

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    data->ctx->domain, _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

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

    ret = sysdb_search_group_by_gid(data, test_ctx->sysdb,
                                    data->ctx->domain, _i + MBO_GROUP_BASE,
                                    data->attrlist, &data->msg);

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

START_TEST (test_sysdb_attrs_to_list)
{
    struct sysdb_attrs *attrs_list[3];
    char **list;
    errno_t ret;

    TALLOC_CTX *test_ctx = talloc_new(NULL);

    attrs_list[0] = sysdb_new_attrs(test_ctx);
    sysdb_attrs_add_string(attrs_list[0], "test_attr", "attr1");
    attrs_list[1] = sysdb_new_attrs(test_ctx);
    sysdb_attrs_add_string(attrs_list[1], "test_attr", "attr2");
    attrs_list[2] = sysdb_new_attrs(test_ctx);
    sysdb_attrs_add_string(attrs_list[2], "nottest_attr", "attr3");

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

    ret = sysdb_update_members(test_ctx->sysdb, test_ctx->domain, user,
                               (const char **)add_groups, NULL);
    fail_unless(ret == EOK, "Could not add groups");
    talloc_zfree(add_groups);

    /* Remove a user from one group and add to another */
    del_groups = talloc_array(test_ctx, char *, 2);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28001");
    del_groups[1] = NULL;
    add_groups = talloc_array(test_ctx, char *, 2);
    add_groups[0] = talloc_strdup(add_groups, "testgroup28003");
    add_groups[1] = NULL;

    ret = sysdb_update_members(test_ctx->sysdb, test_ctx->domain, user,
                               (const char **)add_groups,
                               (const char **)del_groups);
    fail_unless(ret == EOK, "Group replace failed");
    talloc_zfree(add_groups);
    talloc_zfree(del_groups);

    /* Remove a user from two groups */
    del_groups = talloc_array(test_ctx, char *, 3);
    del_groups[0] = talloc_strdup(del_groups, "testgroup28002");
    del_groups[1] = talloc_strdup(del_groups, "testgroup28003");
    del_groups[2] = NULL;

    ret = sysdb_update_members(test_ctx->sysdb, test_ctx->domain,
                               user, NULL,
                               (const char **)del_groups);
    fail_unless(ret == EOK, "Could not remove groups");

    talloc_zfree(test_ctx);
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_user,27000,27010);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27000, 27010);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group, 28000, 28010);

    /* Verify the groups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrnam, 28000, 28010);

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

    /* Verify the change */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_user_attr, 27010, 27020);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_group, 28010, 28020);

    /* Verify the groups were added */

    /* Verify the groups can be queried by GID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrgid, 28010, 28020);

    /* Enumerate the groups */
    tcase_add_test(tc_sysdb, test_sysdb_enumgrent);

    /* Add some members to the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group_member, 28010, 28020);

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

    suite_add_tcase(s, tc_memberof);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
    int ret;
    poptContext pc;
    int failure_count;
    Suite *sysdb_suite;
    SRunner *sr;

    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_MAIN_OPTS
        { NULL }
    };

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

    tests_set_cwd();

    ret = unlink(TESTS_PATH"/"LOCAL_SYSDB_FILE);
    if (ret != EOK && errno != ENOENT) {
        fprintf(stderr, "Could not delete the test ldb file (%d) (%s)\n",
                errno, strerror(errno));
        return EXIT_FAILURE;
    }

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    /* If CK_VERBOSITY is set, use that, otherwise it defaults to CK_NORMAL */
    srunner_run_all(sr, CK_ENV);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    if (failure_count == 0) {
        ret = unlink(TESTS_PATH"/"TEST_CONF_FILE);
        if (ret != EOK) {
            fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }
        ret = unlink(TESTS_PATH"/"LOCAL_SYSDB_FILE);
        if (ret != EOK) {
            fprintf(stderr, "Could not delete the test config ldb file (%d) (%s)\n",
                    errno, strerror(errno));
            return EXIT_FAILURE;
        }

        return EXIT_SUCCESS;
    }
    return  EXIT_FAILURE;
}
