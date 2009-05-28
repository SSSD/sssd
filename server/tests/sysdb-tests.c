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
#include "confdb/confdb_setup.h"
#include "db/sysdb.h"

struct sysdb_test_ctx {
    struct sysdb_ctx *sysdb;
    struct confdb_ctx *confdb;
    struct tevent_context *ev;
    struct sss_domain_info *domains;
};

static int setup_sysdb_tests(struct sysdb_test_ctx **ctx)
{
    struct sysdb_test_ctx *test_ctx;
    char *conf_db;
    int ret;

    const char *val[2];
    val[1] = NULL;

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
    if (ret != EOK) {
        fail("Could not initialize connection to the confdb");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "LOCAL";
    ret = confdb_add_param(test_ctx->confdb, true, "config/domains", "domains", val);
    if (ret != EOK) {
        fail("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true, "config/domains/LOCAL", "magicPrivateGroups", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "3";
    ret = confdb_add_param(test_ctx->confdb, true, "config/domains/LOCAL", "enumerate", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    ret = sysdb_init(test_ctx, test_ctx->ev, test_ctx->confdb, "tests.ldb",
                     &test_ctx->sysdb);
    if (ret != EOK) {
        fail("Could not initialize connection to the sysdb");
        talloc_free(test_ctx);
        return ret;
    }

    ret = confdb_get_domains(test_ctx->confdb, test_ctx,
                             &test_ctx->domains);
    if (ret != EOK) {
        fail("Could not initialize domains");
        talloc_free(test_ctx);
        return ret;
    }

    *ctx = test_ctx;
    return EOK;
}

struct test_data {
    struct sysdb_req *sysreq;
    struct sss_domain_info *domain;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    uid_t uid;
    gid_t gid;

    sysdb_callback_t next_fn;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char *attrval;  /* testing sysdb_get_user_attr */
};

static struct sss_domain_info *get_local_domain(struct sss_domain_info *domlist)
{
    struct sss_domain_info *local = domlist;

    while (local) {
        if (strcmp(local->name, "LOCAL") == 0)
            break;

        local = local->next;
    }

    if (local == NULL) {
        fail("Could not set up the test (missing LOCAL domain)");
        return NULL;
    }

    return local;
}

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

static void test_add_user(struct sysdb_req *req, void *pvt)
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

    ret = sysdb_add_user(req, data->domain,
                         data->username, data->uid, data->gid,
                         gecos, homedir, "/bin/bash",
                         data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
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

    ret = sysdb_legacy_store_user(req, data->domain, data->username, "x",
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

    ret = sysdb_delete_user_by_uid(req, data->domain, data->uid,
                                   data->next_fn, data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_add_group(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_add_group(req, data->domain,
                          data->groupname, data->gid,
                          data->next_fn, data);
    if (ret != EOK) {
        test_return(data, ret, NULL);
    }
}

static void test_add_legacy_group(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct sysdb_ctx *ctx;
    int ret;

    data->sysreq = req;
    ctx = sysdb_req_get_ctx(req);

    ret = sysdb_legacy_store_group(req, data->domain,
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

    group_dn = sysdb_group_dn(ctx, data, "LOCAL", data->groupname);
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

    ret = sysdb_delete_group_by_gid(req, data->domain, data->gid,
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

    ret = sysdb_legacy_add_group_member(req, data->domain,
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

    ret = sysdb_legacy_remove_group_member(req, data->domain,
                                           data->groupname,
                                           data->username,
                                           data->next_fn, data);
    if (ret != EOK) {
        test_return(data, ret, NULL);
    }
}

static void test_getpwent(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    switch (res->count) {
        case 0:
            data->error = ENOENT;
            break;

        case 1:
            data->uid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_UIDNUM, 0);
            break;

        default:
            data->error = EFAULT;
            break;
    }
}

static void test_getgrent(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    switch (res->count) {
        case 0:
            data->error = ENOENT;
            break;

        case 1:
            data->gid = ldb_msg_find_attr_as_uint(res->msgs[0], SYSDB_GIDNUM, 0);
            break;

        default:
            data->error = EFAULT;
            break;
    }
}

static void test_getgrgid(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    switch (res->count) {
        case 0:
            data->error = ENOENT;
            break;

        case 1:
            data->groupname = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);
            break;

        default:
            data->error = EFAULT;
            break;
    }
}

static void test_getpwuid(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    switch (res->count) {
        case 0:
            data->error = ENOENT;
            break;

        case 1:
            data->username = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, 0);
            break;

        default:
            data->error = EFAULT;
            break;
    }
}

static void test_enumgrent(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    const int expected = 30; /* 15 groups + 15 users (we're MPG) */

    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    if (res->count != expected) {
        data->error = EINVAL;
        return;
    }

    data->error = EOK;
}

static void test_enumpwent(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    const int expected = 15; /* 15 groups + 15 users (we're MPG) */

    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    if (res->count != expected) {
        data->error = EINVAL;
        return;
    }

    data->error = EOK;
}

static void test_set_user_attr(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    int ret;

    data->sysreq = req;

    ret = sysdb_set_user_attr(req,
                              data->domain,
                              data->username,
                              data->attrs,
                              data->next_fn,
                              data);
    if (ret != EOK) test_return(data, ret, NULL);
}

static void test_get_user_attr(void *pvt, int error, struct ldb_result *res)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    data->finished = true;

    if (error != EOK) {
        data->error = error;
        return;
    }

    switch (res->count) {
        case 0:
            data->error = ENOENT;
            break;

        case 1:
            data->attrval = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_SHELL, 0);
            break;

        default:
            data->error = EFAULT;
            break;
    }
}

static void test_add_group_member(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;
    const char *username;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        test_return(data, ENOMEM, NULL);
    }

    username = talloc_asprintf(tmp_ctx, "testuser%d", data->uid);
    if (username == NULL) {
        test_return(data, ENOMEM, NULL);
    }
    user_dn = sysdb_user_dn(data->ctx->sysdb,
                            data,
                            data->domain->name,
                            username);
    if (user_dn == NULL) {
        test_return(data, ENOMEM, NULL);
    }
    group_dn = sysdb_group_dn(data->ctx->sysdb,
                              data,
                              data->domain->name,
                              data->groupname);
    if (group_dn == NULL) {
        test_return(data, ENOMEM, NULL);
    }

    data->sysreq = req;

    ret = sysdb_add_group_member(req,
                                 user_dn,
                                 group_dn,
                                 test_return,
                                 data);
    if (ret != EOK) {
        talloc_free(tmp_ctx);
        test_return(data, ret, NULL);
    }
    talloc_free(tmp_ctx);
}

static void test_remove_group_member(struct sysdb_req *req, void *pvt)
{
    struct test_data *data = talloc_get_type(pvt, struct test_data);
    struct ldb_dn *user_dn;
    struct ldb_dn *group_dn;
    const char *username;
    int ret;
    TALLOC_CTX *tmp_ctx;

    tmp_ctx = talloc_new(NULL);
    if (!tmp_ctx) {
        test_return(data, ENOMEM, NULL);
    }

    username = talloc_asprintf(tmp_ctx, "testuser%d", data->uid);
    if (username == NULL) {
        test_return(data, ENOMEM, NULL);
    }
    user_dn = sysdb_user_dn(data->ctx->sysdb,
                            data,
                            data->domain->name,
                            username);
    if (user_dn == NULL) {
        test_return(data, ENOMEM, NULL);
    }
    group_dn = sysdb_group_dn(data->ctx->sysdb,
                              data,
                              data->domain->name,
                              username);
    if (group_dn == NULL) {
        test_return(data, ENOMEM, NULL);
    }

    data->sysreq = req;

    ret = sysdb_remove_group_member(req,
                                    user_dn,
                                    group_dn,
                                    test_return,
                                    data);
    if (ret != EOK) {
        talloc_free(tmp_ctx);
        test_return(data, ret, NULL);
    }

    talloc_free(tmp_ctx);
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
    data->domain = get_local_domain(test_ctx->domains);

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
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->domain = get_local_domain(test_ctx->domains);

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
    const char *attrs[] = { SYSDB_NAME, SYSDB_GIDNUM, NULL };
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

    name = ldb_msg_find_attr_as_string(res->msgs[0], SYSDB_NAME, NULL);
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

    test_gid = ldb_msg_find_attr_as_uint64(res->msgs[0], SYSDB_GIDNUM, 0);
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
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_legacy_group_member, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Failed to add user %s to group %s.",
                        data->username, data->groupname);
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

    group_dn = sysdb_group_dn(test_ctx->sysdb, test_ctx, "LOCAL", groupname);
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
    const char *group_attrs[] = { SYSDB_MEMBER, NULL };

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    group_name = talloc_asprintf(test_ctx, "testgroup%d", _i);
    group = talloc_asprintf(test_ctx,
                            SYSDB_NAME"=%s,"SYSDB_TMPL_GROUP_BASE,
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
                             SYSDB_NAME"=%s,"SYSDB_TMPL_USER_BASE,
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
    el = ldb_msg_find_element(res->msgs[0], SYSDB_MEMBER);
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
    data->domain = get_local_domain(test_ctx->domains);

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
    data->domain = get_local_domain(test_ctx->domains);

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
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_group_by_gid, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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

    data->uid = _i;
    data->gid = _i;
    data->next_fn = test_return;
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_user, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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

    data->uid = _i;
    data->gid = _i;
    data->next_fn = test_return;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_group, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not add group %s", data->groupname);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwnam)
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
    data->next_fn = test_getpwent;
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->sysdb,
                         data->domain,
                         data->username,
                         data->next_fn,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_getpwnam failed for username %d (%s)",
                data->username, ret, strerror(ret));
    fail_unless(data->uid == _i,
                "Did not find the expected UID");

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrnam)
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
    data->next_fn = test_getgrent;
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->sysdb,
                         data->domain,
                         data->groupname,
                         data->next_fn,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_getgrnam failed for groupname %s (%d: %s)",
                data->groupname, ret, strerror(ret));
    fail_unless(data->gid == _i,
                "Did not find the expected GID (found %d expected %d)",
                data->gid, _i);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getgrgid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *groupname = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    groupname = talloc_asprintf(test_ctx, "testgroup%d", _i);
    if (groupname == NULL) {
        fail("Cannot allocate memory");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->next_fn = test_getgrgid;
    data->gid = _i;
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_getgrgid(test_ctx,
                         test_ctx->sysdb,
                         data->domain,
                         data->gid,
                         data->next_fn,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_getgrgid failed for gid %d (%d: %s)",
                data->gid, ret, strerror(ret));
    fail_unless(strcmp(data->groupname, groupname) == 0,
                "Did not find the expected groupname (found %s expected %s)",
                data->groupname, groupname);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_getpwuid)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *username = NULL;

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    username = talloc_asprintf(test_ctx, "testuser%d", _i);
    if (username == NULL) {
        fail("Cannot allocate memory");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->next_fn = test_getpwuid;
    data->uid = _i;
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_getpwuid(test_ctx,
                         test_ctx->sysdb,
                         data->domain,
                         data->uid,
                         data->next_fn,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_getpwuid failed for uid %d (%d: %s)",
                data->uid, ret, strerror(ret));
    fail_unless(strcmp(data->username, username) == 0,
                "Did not find the expected username (found %s expected %s)",
                data->username, username);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumgrent)
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
    data->next_fn = test_enumgrent;
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_enumgrent(test_ctx,
                         test_ctx->sysdb,
                         data->domain,
                         data->next_fn,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_enumgrent failed (%d: %s)",
                ret, strerror(ret));

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_enumpwent)
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
    data->next_fn = test_enumpwent;
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_enumpwent(test_ctx,
                          test_ctx->sysdb,
                          data->domain,
                          NULL,
                          data->next_fn,
                          data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_unless(ret == EOK,
                "sysdb_enumpwent failed (%d: %s)",
                ret, strerror(ret));

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
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->domain = get_local_domain(test_ctx->domains);
    data->next_fn = test_return;

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

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_set_user_attr, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not modify user %s", data->username);

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_get_user_attr)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    int ret;
    const char *attrs[] = { SYSDB_SHELL, NULL };

    /* Setup */
    ret = setup_sysdb_tests(&test_ctx);
    if (ret != EOK) {
        fail("Could not set up the test");
        return;
    }

    data = talloc_zero(test_ctx, struct test_data);
    data->ctx = test_ctx;
    data->username = talloc_asprintf(data, "testuser%d", _i);
    data->domain = get_local_domain(test_ctx->domains);
    data->next_fn = test_get_user_attr;

    ret = sysdb_get_user_attr(data,
                              data->ctx->sysdb,
                              data->domain,
                              data->username,
                              attrs,
                              data->next_fn,
                              data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not get attributes for user %s", data->username);
    fail_if(strcmp(data->attrval, "/bin/ksh"),
            "Got bad attribute value for user %s",
            data->username);

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
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */
    data->domain = get_local_domain(test_ctx->domains);
    data->next_fn = test_return;

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_add_group_member, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

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
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);
    data->uid = _i - 1000; /* the UID of user to add */
    data->domain = get_local_domain(test_ctx->domains);

    ret = sysdb_transaction(data, test_ctx->sysdb,
                            test_remove_group_member, data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    talloc_free(test_ctx);
}
END_TEST

Suite *create_sysdb_suite(void)
{
    Suite *s = suite_create("sysdb");

    TCase *tc_sysdb = tcase_create("SYSDB Tests");

    /* Create a new user (legacy) */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_legacy_user,27000,27010);

    /* Verify the users were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getpwnam, 27000, 27010);

    /* Create a new group (legacy) */
    tcase_add_loop_test(tc_sysdb, test_sysdb_store_legacy_group,27000,27010);

    /* Verify the groups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrnam, 27000, 27010);

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

    /* Remove the other half by gid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group_by_gid, 27000, 27005);

    /* Remove the other half by uid */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user_by_uid, 27000, 27005);

    /* Create a new user */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_user, 27010, 27020);

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
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group, 28010, 28020);

    /* Verify the groups were added */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrnam, 28010, 28020);

    /* Verify the groups can be queried by GID */
    tcase_add_loop_test(tc_sysdb, test_sysdb_getgrgid, 28010, 28020);

    /* Enumerate the groups */
    tcase_add_test(tc_sysdb, test_sysdb_enumgrent);

    /* Add some members to the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_add_group_member, 28010, 28020);

    /* Remove the members from the groups */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_group_member, 28010, 28020);

    /* Remove the users by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_user, 27010, 27020);

    /* Remove the groups by name */
    tcase_add_loop_test(tc_sysdb, test_sysdb_remove_local_group, 28010, 28020);

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
