/*
    Copyright (C) 2015 Red Hat

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>

#include "providers/backend.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp.h"
#include "tests/cmocka/common_mock.h"
#include "tests/common.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/cmocka/data_provider/mock_dp.h"

#define TESTS_PATH "tp_" BASE_FILE_STEM
#define TEST_CONF_DB "test_dp_request.ldb"
#define TEST_DOM_NAME "dp_request_test"
#define TEST_ID_PROVIDER "ldap"

struct test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;
    struct data_provider *provider;
    struct dp_method *dp_methods;
};

static int test_setup(void **state)
{
    struct test_ctx *test_ctx;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_dom_test_ctx(test_ctx, TESTS_PATH, TEST_CONF_DB,
                                         TEST_DOM_NAME, TEST_ID_PROVIDER, NULL);
    assert_non_null(test_ctx->tctx);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    test_ctx->provider = mock_dp(test_ctx, test_ctx->be_ctx);
    test_ctx->dp_methods = mock_dp_get_methods(test_ctx->provider, DPT_ID);

    check_leaks_push(test_ctx);

    *state = test_ctx;

    return 0;
}

static int test_teardown(void **state)
{
    struct test_ctx *test_ctx;

    test_ctx = talloc_get_type_abort(*state, struct test_ctx);
    assert_true(check_leaks_pop(test_ctx));
    talloc_zfree(test_ctx);

    assert_true(leak_check_teardown());
    return 0;
}

static bool is_be_offline_opt = false;

bool __wrap_be_is_offline(struct be_ctx *ctx)
{
    return is_be_offline_opt;
}

#define UID       100001
#define UID2      100002
#define UID_FAIL  100003
#define NAME      "test_user"
#define NAME2     "test_user2"
#define REQ_NAME  "getpwuid"
#define CID 1
#define SENDER_NAME  "sssd.test"

struct method_data
{
    int foo;
};

struct req_data
{
    uid_t uid;
};

struct test_state
{
    uid_t uid;
    const char *name;
};

static void get_name_by_uid_done(struct tevent_context *ev,
                                 struct tevent_timer *tt,
                                 struct timeval tv,
                                 void *pvt);

static struct tevent_req *
get_name_by_uid_send(TALLOC_CTX *mem_ctx,
                     struct method_data *md,
                     struct req_data *req_data,
                     struct dp_req_params *params)
{
    struct tevent_req *req;
    struct test_state *state;
    struct tevent_timer *tt;
    struct timeval tv;

    req = tevent_req_create(mem_ctx, &state, struct test_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    /* Init state of lookup */
    state->uid = req_data->uid;

    /* Mock lookup */
    tv = tevent_timeval_current_ofs(1, 0);
    tt = tevent_add_timer(params->ev, req, tv, get_name_by_uid_done, req);
    if (tt == NULL) {
        return NULL;
    }

    return req;
}

static void get_name_by_uid_done(struct tevent_context *ev,
                                 struct tevent_timer *tt,
                                 struct timeval tv,
                                 void *pvt)
{
    struct tevent_req *req;
    struct test_state *state;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct test_state);

    /* Result */
    if (state->uid == UID) {
        state->name = NAME;
    } else if (state->uid == UID2) {
        state->name = NAME2;
    } else {
        state->name = NULL;
    }
    tevent_req_done(req);
}

struct recv_data
{
    const char *name;
};

static errno_t
get_name_by_uid_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     struct recv_data *recv_data)
{
    struct test_state *state;

    state = tevent_req_data(req, struct test_state);

    if (state->name == NULL) {
        return ENOENT;
    } else {
        recv_data->name = talloc_strdup(recv_data, state->name);
    }
    return EOK;
}

static void test_get_name_by_uid(void **state)
{
    errno_t ret;
    struct test_ctx *test_ctx;
    const char *req_name;
    struct tevent_req *req;
    struct tevent_req *req2;
    struct tevent_req *req3;
    struct method_data *md;
    struct req_data *req_data;
    struct req_data *req_data2;
    struct req_data *req_data3;
    struct recv_data *recv_data;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    md = talloc(test_ctx, struct method_data);

    dp_set_method(test_ctx->dp_methods,
                  DPM_ACCOUNT_HANDLER,
                  get_name_by_uid_send, get_name_by_uid_recv,
                  md,
                  struct method_data, struct req_data, struct recv_data);

    /* Prepare request data #1 */
    req_data = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data);
    req_data->uid = UID; /* We are looking for user by UID */

    /* Prepare request data #2 */
    req_data2 = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data2);
    req_data2->uid = UID_FAIL; /* We are looking for user by UID */

    /* Prepare request data #3 */
    req_data3 = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data3);
    req_data3->uid = UID2; /* We are looking for user by UID */

    /* Send request #1 */
    req = dp_req_send(test_ctx, test_ctx->provider, NULL, REQ_NAME, CID,
                      SENDER_NAME, DPT_ID, DPM_ACCOUNT_HANDLER, 0, req_data,
                      &req_name);
    assert_non_null(req);
    assert_string_equal(req_name, REQ_NAME" #1");
    talloc_zfree(req_name);

    /* Send request #2 */
    req2 = dp_req_send(test_ctx, test_ctx->provider, NULL, REQ_NAME, CID,
                       SENDER_NAME, DPT_ID, DPM_ACCOUNT_HANDLER, 0, req_data2,
                       &req_name);
    assert_non_null(req2);
    assert_string_equal(req_name, REQ_NAME" #2");
    talloc_zfree(req_name);

    /* Send request #3 */
    req3 = dp_req_send(test_ctx, test_ctx->provider, NULL, REQ_NAME, CID,
                       SENDER_NAME, DPT_ID, DPM_ACCOUNT_HANDLER, 0, req_data3,
                       &req_name);
    assert_non_null(req3);
    assert_string_equal(req_name, REQ_NAME" #3");
    talloc_zfree(req_name);

    tevent_loop_wait(test_ctx->tctx->ev);

    /* Receive lookup results */
    ret = dp_req_recv_ptr(test_ctx, req, struct recv_data, &recv_data);
    assert_int_equal(ret, EOK);
    assert_string_equal(recv_data->name, NAME);
    talloc_free(recv_data);

    ret = dp_req_recv_ptr(test_ctx, req2, struct recv_data, &recv_data);
    assert_int_equal(ret, ENOENT);

    ret = dp_req_recv_ptr(test_ctx, req3, struct recv_data, &recv_data);
    assert_int_equal(ret, EOK);
    assert_string_equal(recv_data->name, NAME2);
    talloc_free(recv_data);

    talloc_free(req_data);
    talloc_free(req_data2);
    talloc_free(req_data3);
    talloc_free(req);
    talloc_free(req2);
    talloc_free(req3);
    talloc_free(md);
}

static void test_type_mismatch(void **state)
{
    errno_t ret;
    struct test_ctx *test_ctx;
    const char *req_name;
    struct tevent_req *req;
    struct method_data *md;
    struct req_data *req_data;
    struct recv_data *recv_data;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    md = talloc(test_ctx, struct method_data);
    assert_non_null(md);

    dp_set_method(test_ctx->dp_methods,
                  DPM_ACCOUNT_HANDLER,
                  get_name_by_uid_send, get_name_by_uid_recv,
                  md,
                  struct method_data, struct req_data, struct recv_data);

    /* Prepare request data #1 */
    req_data = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data);
    req_data->uid = UID; /* We are looking for user by UID */

    /* Send request #1 */
    req = dp_req_send(test_ctx, test_ctx->provider, NULL, REQ_NAME, CID,
                      SENDER_NAME, DPT_ID, DPM_ACCOUNT_HANDLER, 0, req_data, &req_name);
    assert_non_null(req);
    assert_string_equal(req_name, REQ_NAME" #1");
    talloc_zfree(req_name);

    tevent_loop_wait(test_ctx->tctx->ev);

    /* Receive lookup results */
    ret = dp_req_recv_ptr(test_ctx, req,
                      struct req_data, /* Wrong data type. */
                      &recv_data);
    assert_int_equal(ret, ERR_INVALID_DATA_TYPE);

    talloc_free(req_data);
    talloc_free(req);
    talloc_free(md);
}

static void test_nonexist_dom(void **state)
{
    errno_t ret;
    struct test_ctx *test_ctx;
    struct tevent_req *req;
    struct method_data *md;
    struct req_data *req_data;
    struct recv_data *recv_data;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    md = talloc(test_ctx, struct method_data);

    dp_set_method(test_ctx->dp_methods,
                  DPM_ACCOUNT_HANDLER,
                  get_name_by_uid_send, get_name_by_uid_recv,
                  md,
                  struct method_data, struct req_data, struct recv_data);

    /* Prepare request data #1 */
    req_data = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data);
    req_data->uid = UID; /* We are looking for user by UID */

    /* Send request #1 */
    req = dp_req_send(test_ctx, test_ctx->provider,
                      "non-existing domain name",
                      REQ_NAME, CID, SENDER_NAME,
                      DPT_ID, DPM_ACCOUNT_HANDLER,
                      0,
                      req_data, NULL);

    assert_non_null(req);

    tevent_loop_wait(test_ctx->tctx->ev);

    /* Receive lookup results */
    ret = dp_req_recv_ptr(test_ctx, req, struct recv_data, &recv_data);
    assert_int_equal(ret, ERR_DOMAIN_NOT_FOUND);

    talloc_free(req_data);
    talloc_free(req);
    talloc_free(md);
}

static void test_fast_reply(void **state)
{
    errno_t ret;
    struct test_ctx *test_ctx;
    struct tevent_req *req;
    struct method_data *md;
    struct req_data *req_data;
    struct recv_data *recv_data;
    bool backup;

    test_ctx = talloc_get_type(*state, struct test_ctx);

    md = talloc(test_ctx, struct method_data);

    dp_set_method(test_ctx->dp_methods,
                  DPM_ACCOUNT_HANDLER,
                  get_name_by_uid_send, get_name_by_uid_recv,
                  md,
                  struct method_data, struct req_data, struct recv_data);

    /* Prepare request data #1 */
    req_data = talloc_zero(test_ctx, struct req_data);
    assert_non_null(req_data);
    req_data->uid = UID; /* We are looking for user by UID */

    backup = is_be_offline_opt;
    is_be_offline_opt = true;

    /* Send request #1 */
    req = dp_req_send(test_ctx, test_ctx->provider, NULL, REQ_NAME,
                      CID, SENDER_NAME,
                      DPT_ID, DPM_ACCOUNT_HANDLER,
                      DP_FAST_REPLY, /* FAST REPLY, don't check online! */
                      req_data, NULL);
    /* Restore */
    is_be_offline_opt = backup;

    assert_non_null(req);

    tevent_loop_wait(test_ctx->tctx->ev);

    /* Receive lookup results */
    ret = dp_req_recv_ptr(test_ctx, req, struct recv_data, &recv_data);
    assert_int_equal(ret, ERR_OFFLINE);
    talloc_free(req);
    talloc_free(md);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    int no_cleanup = 0;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        {"no-cleanup", 'n', POPT_ARG_NONE, &no_cleanup, 0,
         _("Do not delete the test database after a test run"), NULL },
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_get_name_by_uid,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_fast_reply,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_type_mismatch,
                                        test_setup,
                                        test_teardown),
        cmocka_unit_test_setup_teardown(test_nonexist_dom,
                                        test_setup,
                                        test_teardown),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);
    if (rv == 0 && !no_cleanup) {
        test_dom_suite_cleanup(TESTS_PATH, TEST_CONF_DB, TEST_DOM_NAME);
    }

    return rv;
}
