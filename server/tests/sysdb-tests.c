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

#define TESTS_PATH "tests_sysdb"

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

    conf_db = talloc_asprintf(test_ctx, "%s/tests_conf.ldb", TESTS_PATH);
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
                           "config/domains", "domains", val);
    if (ret != EOK) {
        fail("Could not initialize domains placeholder");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "local";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domains/LOCAL", "provider", val);
    if (ret != EOK) {
        fail("Could not initialize provider");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domains/LOCAL", "magicPrivateGroups", val);
    if (ret != EOK) {
        fail("Could not initialize LOCAL domain");
        talloc_free(test_ctx);
        return ret;
    }

    val[0] = "TRUE";
    ret = confdb_add_param(test_ctx->confdb, true,
                           "config/domains/LOCAL", "enumerate", val);
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

    ret = sysdb_domain_init(test_ctx, test_ctx->ev,
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
    struct sysdb_handle *handle;
    struct sysdb_test_ctx *ctx;

    const char *username;
    const char *groupname;
    uid_t uid;
    gid_t gid;
    const char *shell;

    bool finished;
    int error;

    struct sysdb_attrs *attrs;
    const char *attrval;  /* testing sysdb_get_user_attr */
};

static int test_loop(struct test_data *data)
{
    while (!data->finished)
        tevent_loop_once(data->ctx->ev);

    return data->error;
}

static void test_req_done(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);

    data->error = sysdb_transaction_commit_recv(req);
    data->finished = true;
}

static void test_return(struct test_data *data, int error)
{
    struct tevent_req *req;

    if (error != EOK) {
        goto fail;
    }

    req = sysdb_transaction_commit_send(data, data->ev, data->handle);
    if (!req) {
        error = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, test_req_done, data);

    return;

fail:
    /* free transaction */
    talloc_zfree(data->handle);

    data->error = error;
    data->finished = true;
}

static void test_add_user_done(struct tevent_req *subreq);

static void test_add_user(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    char *homedir;
    char *gecos;
    int ret;

    ret = sysdb_transaction_recv(subreq, data, &data->handle);
    talloc_zfree(subreq);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    subreq = sysdb_add_user_send(data, data->ev, data->handle,
                                 data->ctx->domain, data->username,
                                 data->uid, 0,
                                 gecos, homedir, "/bin/bash",
                                 NULL);
    if (!subreq) {
        return test_return(data, ENOMEM);
    }
    tevent_req_set_callback(subreq, test_add_user_done, data);
}

static void test_add_user_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq, struct test_data);
    int ret;

    ret = sysdb_add_user_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_store_user_done(struct tevent_req *subreq);

static void test_store_user(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    char *homedir;
    char *gecos;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    homedir = talloc_asprintf(data, "/home/testuser%d", data->uid);
    gecos = talloc_asprintf(data, "Test User %d", data->uid);

    subreq = sysdb_store_user_send(data, data->ev, data->handle,
                                  data->ctx->domain, data->username, "x",
                                  data->uid, 0,
                                  gecos, homedir,
                                  data->shell ? data->shell : "/bin/bash",
                                  NULL);
    if (!subreq) {
        test_return(data, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, test_store_user_done, data);
}

static void test_store_user_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq, struct test_data);
    int ret;

    ret = sysdb_store_user_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_user_done(struct tevent_req *subreq);

static void test_remove_user(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct ldb_dn *user_dn;
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    user_dn = sysdb_user_dn(data->ctx->sysdb, data, "LOCAL", data->username);
    if (!user_dn) return test_return(data, ENOMEM);

    subreq = sysdb_delete_entry_send(data, data->ev, data->handle, user_dn, true);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_user_done, data);
}

static void test_remove_user_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_user_by_uid_done(struct tevent_req *subreq);

static void test_remove_user_by_uid(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_delete_user_by_uid_send(data,
                                           data->ev, data->handle,
                                           data->ctx->domain, data->uid,
                                           true);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_user_by_uid_done, data);
}

static void test_remove_user_by_uid_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_user_by_uid_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_nonexistent_group_done(struct tevent_req *subreq);

static void test_remove_nonexistent_group(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_delete_group_by_gid_send(data,
                                           data->ev, data->handle,
                                           data->ctx->domain, data->uid,
                                           false);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_nonexistent_group_done, data);
}

static void test_remove_nonexistent_group_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_group_by_gid_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_nonexistent_user_done(struct tevent_req *subreq);

static void test_remove_nonexistent_user(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_delete_user_by_uid_send(data,
                                           data->ev, data->handle,
                                           data->ctx->domain, data->uid,
                                           false);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_nonexistent_user_done, data);
}

static void test_remove_nonexistent_user_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_user_by_uid_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_add_group_done(struct tevent_req *subreq);

static void test_add_group(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req,
                                                      struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_add_group_send(data, data->ev, data->handle,
                                  data->ctx->domain, data->groupname,
                                  data->gid, NULL);
    if (!subreq) {
        test_return(data, ret);
    }
    tevent_req_set_callback(subreq, test_add_group_done, data);
}

static void test_add_group_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq, struct test_data);
    int ret;

    ret = sysdb_add_group_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_store_group_done(struct tevent_req *subreq);

static void test_store_group(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_store_group_send(data, data->ev, data->handle,
                                    data->ctx->domain, data->groupname,
                                    data->gid, NULL, NULL, NULL);
    if (!subreq) {
        test_return(data, ret);
    }
    tevent_req_set_callback(subreq, test_store_group_done, data);
}

static void test_store_group_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq, struct test_data);
    int ret;

    ret = sysdb_store_group_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_group_done(struct tevent_req *subreq);

static void test_remove_group(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    struct ldb_dn *group_dn;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    group_dn = sysdb_group_dn(data->ctx->sysdb, data, "LOCAL", data->groupname);
    if (!group_dn) return test_return(data, ENOMEM);

    subreq = sysdb_delete_entry_send(data, data->ev, data->handle, group_dn, true);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_group_done, data);
}

static void test_remove_group_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_entry_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
}

static void test_remove_group_by_gid_done(struct tevent_req *subreq);
static void test_remove_group_by_gid(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_delete_group_by_gid_send(data, data->ev, data->handle,
                                            data->ctx->domain, data->gid,
                                            true);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_remove_group_by_gid_done, data);
}

static void test_remove_group_by_gid_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_delete_group_by_gid_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
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
    const int expected = 20; /* 10 groups + 10 users (we're MPG) */

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
    const int expected = 10;

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

static void test_set_user_attr_done(struct tevent_req *subreq);
static void test_set_user_attr(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    subreq = sysdb_set_user_attr_send(data, data->ev, data->handle,
                                      data->ctx->domain, data->username,
                                      data->attrs, SYSDB_MOD_REP);
    if (!subreq) return test_return(data, ENOMEM);

    tevent_req_set_callback(subreq, test_set_user_attr_done, data);
}

static void test_set_user_attr_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret;

    ret = sysdb_set_user_attr_recv(subreq);
    talloc_zfree(subreq);

    return test_return(data, ret);
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

static void test_add_group_member_done(struct tevent_req *subreq);

static void test_add_group_member(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    const char *username;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        test_return(data, ENOMEM);
    }

    subreq = sysdb_add_group_member_send(data, data->ev,
                                         data->handle, data->ctx->domain,
                                         data->groupname, username);
    if (!subreq) {
        test_return(data, ENOMEM);
    }

    tevent_req_set_callback(subreq, test_add_group_member_done, data);
}

static void test_add_group_member_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret = sysdb_add_group_member_recv(subreq);

    test_return(data, ret);
}

static void test_remove_group_member_done(struct tevent_req *subreq);

static void test_remove_group_member(struct tevent_req *req)
{
    struct test_data *data = tevent_req_callback_data(req, struct test_data);
    struct tevent_req *subreq;
    const char *username;
    int ret;

    ret = sysdb_transaction_recv(req, data, &data->handle);
    if (ret != EOK) {
        return test_return(data, ret);
    }

    username = talloc_asprintf(data, "testuser%d", data->uid);
    if (username == NULL) {
        test_return(data, ENOMEM);
    }

    subreq = sysdb_remove_group_member_send(data, data->ev,
                                            data->handle, data->ctx->domain,
                                            data->groupname, username);
    if (!subreq) {
        test_return(data, ENOMEM);
    }

    tevent_req_set_callback(subreq, test_remove_group_member_done, data);
}

static void test_remove_group_member_done(struct tevent_req *subreq)
{
    struct test_data *data = tevent_req_callback_data(subreq,
                                                      struct test_data);
    int ret = sysdb_remove_group_member_recv(subreq);

    test_return(data, ret);
}

START_TEST (test_sysdb_store_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_store_user, data);

        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_user_existing)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_store_user, data);

        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not store user %s", data->username);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_store_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_store_group, data);

        ret = test_loop(data);
    }

    fail_if(ret != EOK, "Could not store POSIX group #%d", _i);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_local_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_user, data);

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
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_user_by_uid, data);

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
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_group, data);

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
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_group_by_gid, data);

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
    struct tevent_req *subreq;
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

    subreq = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!subreq) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(subreq, test_add_user, data);

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
    struct tevent_req *subreq;
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

    subreq = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!subreq) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(subreq, test_add_group, data);

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
    data->username = talloc_asprintf(data, "testuser%d", _i);

    ret = sysdb_getpwnam(test_ctx,
                         test_ctx->sysdb,
                         data->ctx->domain,
                         data->username,
                         test_getpwent,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    if (ret) {
        fail("sysdb_getpwnam failed for username %s (%d: %s)",
             data->username, ret, strerror(ret));
        goto done;
    }
    fail_unless(data->uid == _i,
                "Did not find the expected UID");
done:
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
    data->groupname = talloc_asprintf(data, "testgroup%d", _i);

    ret = sysdb_getgrnam(test_ctx,
                         test_ctx->sysdb,
                         data->ctx->domain,
                         data->groupname,
                         test_getgrent,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    if (ret) {
        fail("sysdb_getgrnam failed for groupname %s (%d: %s)",
             data->groupname, ret, strerror(ret));
        goto done;
    }
    fail_unless(data->gid == _i,
                "Did not find the expected GID (found %d expected %d)",
                data->gid, _i);
done:
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
    data->gid = _i;

    ret = sysdb_getgrgid(test_ctx,
                         test_ctx->sysdb,
                         data->ctx->domain,
                         data->gid,
                         test_getgrgid,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    if (ret) {
        fail("sysdb_getgrgid failed for gid %d (%d: %s)",
             data->gid, ret, strerror(ret));
        goto done;
    }
    fail_unless(strcmp(data->groupname, groupname) == 0,
                "Did not find the expected groupname (found %s expected %s)",
                data->groupname, groupname);
done:
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
    data->uid = _i;

    ret = sysdb_getpwuid(test_ctx,
                         test_ctx->sysdb,
                         data->ctx->domain,
                         data->uid,
                         test_getpwuid,
                         data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    if (ret) {
        fail("sysdb_getpwuid failed for uid %d (%d: %s)",
             data->uid, ret, strerror(ret));
        goto done;
    }

    fail_unless(strcmp(data->username, username) == 0,
                "Did not find the expected username (found %s expected %s)",
                data->username, username);
done:
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

    ret = sysdb_enumgrent(test_ctx,
                         test_ctx->sysdb,
                         data->ctx->domain,
                         test_enumgrent,
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

    ret = sysdb_enumpwent(test_ctx,
                          test_ctx->sysdb,
                          data->ctx->domain,
                          NULL,
                          test_enumpwent,
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
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_set_user_attr, data);

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

    ret = sysdb_get_user_attr(data,
                              data->ctx->sysdb,
                              data->ctx->domain,
                              data->username,
                              attrs,
                              test_get_user_attr,
                              data);
    if (ret == EOK) {
        ret = test_loop(data);
    }

    if (ret) {
        fail("Could not get attributes for user %s", data->username);
        goto done;
    }
    fail_if(strcmp(data->attrval, "/bin/ksh"),
            "Got bad attribute value for user %s",
            data->username);
done:
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_add_group_member)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_add_group_member, data);

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
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_group_member, data);

        ret = test_loop(data);
    }

    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_user)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_nonexistent_user, data);

        ret = test_loop(data);
    }

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
}
END_TEST

START_TEST (test_sysdb_remove_nonexistent_group)
{
    struct sysdb_test_ctx *test_ctx;
    struct test_data *data;
    struct tevent_req *req;
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

    req = sysdb_transaction_send(data, data->ev, test_ctx->sysdb);
    if (!req) {
        ret = ENOMEM;
    }

    if (ret == EOK) {
        tevent_req_set_callback(req, test_remove_nonexistent_group, data);

        ret = test_loop(data);
    }

    fail_if(ret != ENOENT, "Unexpected return code %d, expected ENOENT", ret);
    talloc_free(test_ctx);
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
