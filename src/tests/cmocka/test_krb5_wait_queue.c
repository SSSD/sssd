/*
    Copyright (C) 2015 Red Hat

    SSSD tests: Kerberos wait queue tests

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
#include <stdlib.h>
#include <security/pam_modules.h>

#include "util/util.h"
#include "providers/krb5/krb5_common.h"
#include "providers/krb5/krb5_auth.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"

struct krb5_mocked_auth_state {
    const char *user;
    time_t us_delay;
    int ret;
    int pam_status;
    int dp_err;
};

static void krb5_mocked_auth_done(struct tevent_context *ev,
                                  struct tevent_timer *tt,
                                  struct timeval tv,
                                  void *pvt);

struct tevent_req *krb5_auth_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct pam_data *pd,
                                  struct krb5_ctx *krb5_ctx)
{
    struct tevent_req *req;
    struct krb5_mocked_auth_state *state;
    struct tevent_timer *tt;
    struct timeval tv;

    req = tevent_req_create(mem_ctx, &state, struct krb5_mocked_auth_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->user = sss_mock_ptr_type(const char *);
    state->us_delay = sss_mock_type(time_t);
    state->ret = sss_mock_type(int);
    state->pam_status = sss_mock_type(int);
    state->dp_err = sss_mock_type(int);

    tv = tevent_timeval_current_ofs(0, state->us_delay);

    tt = tevent_add_timer(ev, req, tv, krb5_mocked_auth_done, req);
    if (tt == NULL) {
        return NULL;
    }

    return req;
}

static void krb5_mocked_auth_done(struct tevent_context *ev,
                                  struct tevent_timer *tt,
                                  struct timeval tv,
                                  void *pvt)
{
    struct tevent_req *req;
    struct krb5_mocked_auth_state *state;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct krb5_mocked_auth_state);

    DEBUG(SSSDBG_TRACE_LIBS, "Finished auth request of %s\n", state->user);

    if (state->ret == 0) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, state->ret);
    }
}

int krb5_auth_recv(struct tevent_req *req,
                   int *_pam_status,
                   int *_dp_err)
{
    struct krb5_mocked_auth_state *state;

    state = tevent_req_data(req, struct krb5_mocked_auth_state);

    if (_pam_status != NULL) {
        *_pam_status = state->pam_status;
    }

    if (_dp_err != NULL) {
        *_dp_err = state->dp_err;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct test_krb5_wait_queue {
    struct sss_test_ctx *tctx;
    int num_auths;
    int num_finished_auths;

    struct be_ctx *be_ctx;
    struct pam_data *pd;
    struct krb5_ctx *krb5_ctx;
};

static int test_krb5_wait_queue_setup(void **state)
{
    struct test_krb5_wait_queue *test_ctx;

    test_ctx = talloc_zero(global_talloc_context,
                           struct test_krb5_wait_queue);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_ev_test_ctx(test_ctx);
    assert_non_null(test_ctx);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->pd = talloc_zero(test_ctx, struct pam_data);
    assert_non_null(test_ctx->pd);

    test_ctx->krb5_ctx = talloc_zero(test_ctx, struct krb5_ctx);
    assert_non_null(test_ctx->krb5_ctx);

    *state = test_ctx;
    return 0;
}

static int test_krb5_wait_queue_teardown(void **state)
{
    struct test_krb5_wait_queue *test_ctx =
        talloc_get_type(*state, struct test_krb5_wait_queue);

    talloc_free(test_ctx);
    return 0;
}

static void test_krb5_wait_mock(struct test_krb5_wait_queue *test_ctx,
                                const char *username,
                                time_t us_delay,
                                int ret,
                                int pam_status,
                                int dp_err)
{
    test_ctx->pd->user = discard_const(username);

    will_return(krb5_auth_send, username);
    will_return(krb5_auth_send, us_delay);
    will_return(krb5_auth_send, ret);
    will_return(krb5_auth_send, pam_status);
    will_return(krb5_auth_send, dp_err);
}

static void test_krb5_wait_mock_success(struct test_krb5_wait_queue *test_ctx,
                                        const char *username)
{
    return test_krb5_wait_mock(test_ctx, username, 200, 0, 0, 0);
}

static void test_krb5_wait_queue_single_done(struct tevent_req *req);

static void test_krb5_wait_queue_single(void **state)
{
    errno_t ret;
    struct tevent_req *req;
    struct test_krb5_wait_queue *test_ctx =
        talloc_get_type(*state, struct test_krb5_wait_queue);

    test_krb5_wait_mock_success(test_ctx, "krb5_user");

    req = krb5_auth_queue_send(test_ctx,
                               test_ctx->tctx->ev,
                               test_ctx->be_ctx,
                               test_ctx->pd,
                               test_ctx->krb5_ctx);
    assert_non_null(req);
    tevent_req_set_callback(req, test_krb5_wait_queue_single_done, test_ctx);

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_krb5_wait_queue_single_done(struct tevent_req *req)
{
    struct test_krb5_wait_queue *test_ctx = \
        tevent_req_callback_data(req, struct test_krb5_wait_queue);
    errno_t ret;
    int pam_status;
    int dp_err;

    ret = krb5_auth_queue_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    assert_int_equal(ret, EOK);

    test_ev_done(test_ctx->tctx, EOK);
}

static void test_krb5_wait_queue_multi_done(struct tevent_req *req);

static void test_krb5_wait_queue_multi(void **state)
{
    int i;
    errno_t ret;
    struct tevent_req *req;
    struct test_krb5_wait_queue *test_ctx =
        talloc_get_type(*state, struct test_krb5_wait_queue);

    test_ctx->num_auths = 1000;

    for (i=0; i < test_ctx->num_auths; i++) {
        test_krb5_wait_mock_success(test_ctx, "krb5_user");

        req = krb5_auth_queue_send(test_ctx,
                                   test_ctx->tctx->ev,
                                   test_ctx->be_ctx,
                                   test_ctx->pd,
                                   test_ctx->krb5_ctx);
        assert_non_null(req);
        tevent_req_set_callback(req, test_krb5_wait_queue_multi_done, test_ctx);
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_krb5_wait_queue_multi_done(struct tevent_req *req)
{
    struct test_krb5_wait_queue *test_ctx = \
        tevent_req_callback_data(req, struct test_krb5_wait_queue);
    errno_t ret;
    int pam_status;
    int dp_err;

    ret = krb5_auth_queue_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    assert_int_equal(ret, EOK);

    test_ctx->num_finished_auths++;

    if (test_ctx->num_finished_auths == test_ctx->num_auths) {
        test_ev_done(test_ctx->tctx, EOK);
    }
}

static void test_krb5_wait_queue_fail_odd_done(struct tevent_req *req);

static void test_krb5_wait_queue_fail_odd(void **state)
{
    int i;
    errno_t ret;
    struct tevent_req *req;
    struct test_krb5_wait_queue *test_ctx =
        talloc_get_type(*state, struct test_krb5_wait_queue);

    test_ctx->num_auths = 10;

    for (i=0; i < test_ctx->num_auths; i++) {
        test_krb5_wait_mock(test_ctx, "krb5_user", 0, i+1 % 2, PAM_SUCCESS, 0);

        req = krb5_auth_queue_send(test_ctx,
                                   test_ctx->tctx->ev,
                                   test_ctx->be_ctx,
                                   test_ctx->pd,
                                   test_ctx->krb5_ctx);
        assert_non_null(req);
        tevent_req_set_callback(req, test_krb5_wait_queue_fail_odd_done, test_ctx);
    }

    ret = test_ev_loop(test_ctx->tctx);
    assert_int_equal(ret, EOK);
}

static void test_krb5_wait_queue_fail_odd_done(struct tevent_req *req)
{
    struct test_krb5_wait_queue *test_ctx = \
        tevent_req_callback_data(req, struct test_krb5_wait_queue);
    errno_t ret;
    int pam_status;
    int dp_err;

    ret = krb5_auth_queue_recv(req, &pam_status, &dp_err);
    talloc_free(req);
    assert_int_equal(ret, test_ctx->num_finished_auths+1 % 2);

    test_ctx->num_finished_auths++;

    if (test_ctx->num_finished_auths == test_ctx->num_auths) {
        test_ev_done(test_ctx->tctx, EOK);
    }
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
        /* Run a single auth request */
        cmocka_unit_test_setup_teardown(test_krb5_wait_queue_single,
                                        test_krb5_wait_queue_setup,
                                        test_krb5_wait_queue_teardown),

        /* Run multiple auth requests */
        cmocka_unit_test_setup_teardown(test_krb5_wait_queue_multi,
                                        test_krb5_wait_queue_setup,
                                        test_krb5_wait_queue_teardown),

        /* Make sure that all requests in queue run even if some fail */
        cmocka_unit_test_setup_teardown(test_krb5_wait_queue_fail_odd,
                                        test_krb5_wait_queue_setup,
                                        test_krb5_wait_queue_teardown),
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
