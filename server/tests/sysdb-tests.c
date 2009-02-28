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
#include "util/util.h"
#include "confdb/confdb.h"
#include "db/sysdb.h"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
};

static int setup_sysdb_tests(struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

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

    conf_db = talloc_asprintf(test_ctx, "tests_conf.ldb");
    if (conf_db == NULL) {
        fail("Out of memory, aborting!");
        talloc_free(test_ctx);
        return ENOMEM;
    }
    DEBUG(3, ("CONFDB: %s\n", conf_db));

    /* Connect to the conf db */
    ret = confdb_init(test_ctx, test_ctx->ev, &test_ctx->confdb, conf_db);
    if(ret != EOK) {
        fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sysdb_init(test_ctx, test_ctx->ev, test_ctx->confdb, "tests.ldb",
                     &test_ctx->sysdb);
    if(ret != EOK) {
        fail("Could not initialize connection to the sysdb");
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

struct test_data {
    struct sysdb_req *sysreq;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    uid_t uid;
    gid_t gid;

    sysdb_callback_t next_fn;

    bool finished;
    int error;
};

static int test_loop(struct test_data *data)
{
    while (!data->finished)
        tevent_loop_once(data->ctx->ev);

    return data->error;
}

static void test_return(void *pvt, int error, struct ldb_result *ignore)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    const char *err = "Success";

    if (error != EOK) err = "Operation failed";

    sysdb_transaction_done(data->sysreq, error);

    data->error = error;
    data->finished = true;
}

static void test_add_legacy_user(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    char *homedir;
    char *gecos;
    int ret;

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_store_user(req, "LOCAL", data->username, "x",
                                  data->uid, data->gid, gecos, homedir,
                                  "/bin/bash", data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_remove_user(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    struct ldb_dn *user_dn;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    user_dn = sysdb_user_dn(ctx, data, "LOCAL", data->username);
    if (!user_dn) return test_return(data, ENOMEM, NULL);

    ret = sysdb_delete_entry(req, user_dn, data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_remove_user_by_uid(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_delete_user_by_uid(req, "LOCAL", data->uid,
                                   data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_add_legacy_group(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_store_group(req, "LOCAL",
                                   data->groupname,
                                   data->gid, NULL,
                                   data->next_fn, data);
    if (ret != EOK) {
        test_return(data, ret, NULL);
    }
}

static void test_remove_group(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    struct ldb_dn *group_dn;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    group_dn = sysdb_user_dn(ctx, data, "LOCAL", data->groupname);
    if (!group_dn) return test_return(data, ENOMEM, NULL);

    ret = sysdb_delete_entry(req, group_dn, data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_remove_group_by_gid(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_delete_group_by_gid(req, "LOCAL", data->gid,
                                    data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_add_legacy_group_member(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_add_group_member(req, "LOCAL",
                                        data->groupname,
                                        data->username,
                                        data->next_fn, data);
    if (ret != EOK) {
        test_return(data, ret, NULL);
    }
}

static void test_remove_legacy_group_member(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_remove_group_member(req, "LOCAL",
                                           data->groupname,
                                           data->username,
                                           data->next_fn, data);
    if (ret != EOK) {
        test_return(data, ret, NULL);
    }
}

START_TEST (test_sysdb_store_legacy_user)
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
    data->uid = _i;
    data->gid = _i;
    data->next_fn = test_return;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_legacy_user, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not store legacy user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_legacy_group)
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
    data->gid = _i;
    data->next_fn = test_return;

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_legacy_group, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not store POSIX group #%d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_local_group)
{
    int ret;
    struct sysdb_test_ctx *test_ctx;
    struct ldb_result *res;
    struct ldb_dn *base_group_dn;
    const char *attrs[] = { SYSDB_GR_NAME, SYSDB_GR_GIDNUM, NULL };
    const char *name;
    char *expected_group;
    gid_t test_gid;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    expected_group = talloc_asprintf(test_ctx, "testgroup%d", _i);
    fail_if(expected_group == NULL, "Could not allocate expected_group");

    /* Set up the base DN */
    base_group_dn = ldb_dn_new_fmt(test_ctx, sysdb_ctx_get_ldb(test_ctx->sysdb),
                                   SYSDB_TMPL_GROUP_BASE, "LOCAL");
    if (base_group_dn == NULL) {
        fail("Could not create basedn for LOCAL groups");
        return;
    }

    /* Look up the group by gid */
    ret = ldb_search(sysdb_ctx_get_ldb(test_ctx->sysdb), test_ctx,
                     &res, base_group_dn, LDB_SCOPE_ONELEVEL,
                     attrs, SYSDB_GRGID_FILTER, (unsigned long)_i);
    if (ret != LDB_SUCCESS) {
        fail("Could not locate group %d", _i);
        return;
    }

    if (res->count < 1) {
        fail("Local group %d doesn't exist.\n", _i);
        return;
    }
    else if (res->count > 1) {
        fail("More than one group shared gid %d", _i);
        return;
    }

    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_GR_NAME, NULL);
    fail_unless(strcmp(name, expected_group) == 0,
                "Returned group name was %s, expecting %s",
                name, expected_group);
    talloc_free(res);

    /* Look up the group by name */
    ret = ldb_search(sysdb_ctx_get_ldb(test_ctx->sysdb), test_ctx,
                     &res, base_group_dn, LDB_SCOPE_ONELEVEL,
                     attrs, SYSDB_GRNAM_FILTER, expected_group);
    if (ret != LDB_SUCCESS) {
        fail("Could not locate group %d", _i);
        return;
    }

    if (res->count < 1) {
        fail("Local group %s doesn't exist.", expected_group);
        return;
    }
    else if (res->count > 1) {
        fail("More than one group shared name %s", expected_group);
        return;
    }

    test_gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GR_GIDNUM, 0);
    fail_unless(test_gid == _i,
                "Returned group id was %lu, expecting %lu",
                test_gid, _i);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_legacy_group_member)
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
    data->next_fn = test_return;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_legacy_group_member, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Failed to add user %s to group %s.",
                        data->username, data->groupname, ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_verify_legacy_group_members)
{
    char found_group;
    int ret, i;
    struct sysdb_test_ctx *test_ctx;
    char *username;
    char *groupname;
    struct ldb_dn *group_dn;
    struct ldb_dn *user_dn;
    struct ldb_result *res;
    struct ldb_message_element *el;
    const char *group_attrs[] = { SYSDB_LEGACY_MEMBER, NULL };

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);
    fail_if (username == NULL, "Could not allocate username");

    user_dn = sysdb_user_dn(test_ctx->sysdb, test_ctx, "LOCAL", username);
    fail_if(user_dn == NULL, "Could not create user_dn object");

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    fail_if (groupname == NULL, "Could not allocate groupname");

    group_dn = sysdb_user_dn(test_ctx->sysdb, test_ctx, "LOCAL", groupname);
    fail_if(group_dn == NULL, "Could not create group_dn object");

    /* Look up the group by name */
    ret = ldb_search(sysdb_ctx_get_ldb(test_ctx->sysdb), test_ctx,
                     &res, group_dn, LDB_SCOPE_BASE,
                     group_attrs, SYSDB_GRNAM_FILTER, groupname);
    if (ret != LDB_SUCCESS) {
        fail("Could not locate group %d", _i);
        return;
    }

    if (res->count < 1) {
        fail("Local group %s doesn't exist.", groupname);
        return;
    }
    else if (res->count > 1) {
        fail("More than one group shared name testgroup");
        return;
    }

    /* Check the members for the requested user */
    found_group = i = 0;
    el = ldb_msg_find_element(res->msgs[0], SYSDB_LEGACY_MEMBER);
    if (el && el->num_values > 0) {
        while (i < el->num_values && !found_group) {
            struct ldb_val v = el->values[i];
            char *value = talloc_strndup(test_ctx, (char *)v.data, v.length);
            if (strcmp(value, username) == 0) {
                found_group = 1;
            }
            talloc_free(value);
            i++;
        }
    }
    else {
        fail("No member attributes for group testgroup");
    }

    fail_unless(found_group == 1, "testgroup does not have %s as a member",
                                  username);
}
END_TEST

#if 0
START_TEST (test_sysdb_add_invalid_member)
{
    char found_group;
    int ret, i;
    struct sysdb_test_ctx *test_ctx;
    char *username;
    char *member;
    char *group;
    char *group_name;
    struct ldb_dn *group_dn;
    struct ldb_result *res;
    struct ldb_message_element *el;
    const char *group_attrs[] = { SYSDB_GR_MEMBER, NULL };

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    group_name = talloc_asprintf(test_ctx, "testgroup%d", _i);
    group = talloc_asprintf(test_ctx,
                            SYSDB_GR_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
                            group_name, "LOCAL");
    fail_if(group == NULL, "Could not allocate group dn");

    /* Add nonexistent user to test group */
    username = talloc_asprintf(test_ctx, "nonexistentuser%d", _i);
    ret = sysdb_add_user_to_group(test_ctx,
                                            test_ctx->sysdb,
                                            "LOCAL",
                                            group,
                                            username);
    fail_if(ret == EOK,
            "Unexpected success adding user %s to group testgroup."
            "Error was: %d", username, ret);

/* Verify that the member wasn't added anyway */

    member = talloc_asprintf(test_ctx,
                             SYSDB_PW_NAME"=%s,"SYSDB_TMPL_USER_BASE,
                             username, "LOCAL");
    fail_if(member == NULL, "Could not allocate member dn");

    group_dn = ldb_dn_new_fmt(test_ctx, sysdb_ctx_get_ldb(test_ctx->sysdb), group);
    fail_if(group_dn == NULL, "Could not create group_dn object");

    /* Look up the group by name */
    ret = ldb_search(sysdb_ctx_get_ldb(test_ctx->sysdb), test_ctx,
                     &res, group_dn, LDB_SCOPE_BASE,
                     group_attrs, SYSDB_GRNAM_FILTER, group_name);
    if (ret != LDB_SUCCESS) {
        fail("Could not locate group %d", _i);
        return;
    }

    if (res->count < 1) {
        fail("Local group %s doesn't exist.", group_name);
        return;
    }
    else if (res->count > 1) {
        fail("More than one group shared name %s", group_name);
        return;
    }

    /* Check the members for the requested user */
    found_group = i = 0;
    el = ldb_msg_find_element(res->msgs[0], SYSDB_GR_MEMBER);
    if (el && el->num_values > 0) {
        while (i < el->num_values && !found_group) {
            struct ldb_val v = el->values[i];
            char *value = talloc_strndup(test_ctx, (char *)v.data, v.length);
            if (strcmp(value, member) == 0) {
                found_group = 1;
            }
            talloc_free(value);
            i++;
        }
    }
    else {
        fail("No member attributes for group testgroup");
    }

    fail_if(found_group == 1, "testgroup has added %s as a member", username);
    talloc_free(test_ctx);
}
END_TEST
#endif

START_TEST (test_sysdb_remove_legacy_group_member)
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
    data->next_fn = test_return;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_legacy_group_member, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Failed to remove user %s to group %s.",
                        data->username, data->groupname, ret);
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
    data->next_fn = test_return;
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_user, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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
    data->next_fn = test_return;
    data->uid = _i;

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_user_by_uid, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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
    data->next_fn = test_return;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_group, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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
    data->next_fn = test_return;
    data->gid = _i;

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_group_by_gid, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not remove group with gid %d", _i);
    talloc_free(test_ctx);
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_legacy_user,27000,27010);

    /* Create a new group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_legacy_group,27000,27010);

    /* Verify that the new group exists */
    tcase_add_loop_test(tc_sysdb, test_sysdb_get_local_group,27000,27010);

    /* Add users to the group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_legacy_group_member, 27000, 27010);

    /* Verify member and memberOf */
    tcase_add_loop_test(tc_sysdb, test_sysdb_verify_legacy_group_members, 27000, 27010);
#if 0
    /* A negative test: add nonexistent users as members of a group */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_invalid_member, 27000, 27010);
#endif
    /* Remove users from their groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_legacy_group_member, 27000, 27010);

    /* Remove half of the groups by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group, 27000, 27005);

    /* Remove the other half by gid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 27005, 27010);


    /* Remove half of the users by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user, 27000, 27005);

    /* Remove the other half by uid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user_by_uid, 27005, 27010);

/* Add all test cases to the test suite */
    suite_add_tcase(s, tc_sysdb);

    return s;
}

int main(int argc, const char *argv[]) {
    int opt;
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

    sysdb_suite = create_sysdb_suite();
    sr = srunner_create(sysdb_suite);
    srunner_run_all(sr, CK_VERBOSE);
    failure_count = srunner_ntests_failed(sr);
    srunner_free(sr);
    return (failure_count==0 ? EXIT_SUCCESS : EXIT_FAILURE);
}
