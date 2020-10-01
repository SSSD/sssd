/*
    Copyright (C) 2017 Red Hat

    SSSD tests: Test KCM wait queue

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

#include "config.h"

#include <stdio.h>
#include <popt.h>

#include "util/util.h"
#include "util/util_creds.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_resp.h"
#include "responder/kcm/kcmsrv_pvt.h"

#define INVALID_ID      -1
#define FAST_REQ_ID     0
#define SLOW_REQ_ID     1

#define FAST_REQ_DELAY  1
#define SLOW_REQ_DELAY  2

/* register_cli_protocol_version is required in test since it links with
 * responder_common.c module
 */
struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version responder_test_cli_protocol_version[] = {
        { 0, NULL, NULL }
    };

    return responder_test_cli_protocol_version;
}

struct timed_request_state {
    struct tevent_context *ev;
    struct resp_ctx *rctx;
    struct kcm_ops_queue_ctx *qctx;
    struct cli_creds *client;
    int delay;
    int req_id;

    struct kcm_ops_queue_entry *queue_entry;
};

static void timed_request_start(struct tevent_req *subreq);
static void timed_request_done(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval current_time,
                               void *pvt);

static struct tevent_req *timed_request_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct resp_ctx *rctx,
                                             struct kcm_ops_queue_ctx *qctx,
                                             struct cli_creds *client,
                                             int delay,
                                             int req_id)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct timed_request_state *state;

    req = tevent_req_create(mem_ctx, &state, struct timed_request_state);
    if (req == NULL) {
        return NULL;
    }
    state->ev = ev;
    state->rctx = rctx;
    state->qctx = qctx;
    state->client = client;
    state->delay = delay;
    state->req_id = req_id;

    DEBUG(SSSDBG_TRACE_ALL, "Request %p with delay %d\n", req, delay);

    subreq = kcm_op_queue_send(state, ev, qctx, client);
    if (subreq == NULL) {
        return NULL;
    }
    tevent_req_set_callback(subreq, timed_request_start, req);

    return req;
}

static void timed_request_start(struct tevent_req *subreq)
{
    struct timeval tv;
    struct tevent_timer *timeout = NULL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct timed_request_state *state = tevent_req_data(req,
                                                struct timed_request_state);
    errno_t ret;

    ret = kcm_op_queue_recv(subreq, state, &state->queue_entry);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tv = tevent_timeval_current_ofs(state->delay, 0);
    timeout = tevent_add_timer(state->ev, state, tv, timed_request_done, req);
    if (timeout == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    return;
}

static void timed_request_done(struct tevent_context *ev,
                               struct tevent_timer *te,
                               struct timeval current_time,
                               void *pvt)
{
    struct tevent_req *req = talloc_get_type(pvt, struct tevent_req);
    DEBUG(SSSDBG_TRACE_ALL, "Request %p done\n", req);
    tevent_req_done(req);
}

static errno_t timed_request_recv(struct tevent_req *req,
                                  int *req_id)
{
    struct timed_request_state *state = tevent_req_data(req,
                                                struct timed_request_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);
    *req_id = state->req_id;
    return EOK;
}

struct test_ctx {
    struct resp_ctx *rctx;
    struct kcm_ops_queue_ctx *qctx;
    struct kcm_ctx *kctx;
    struct tevent_context *ev;

    int *req_ids;

    int num_requests;
    int finished_requests;
    bool done;
    errno_t error;
};

struct kcm_ctx *
mock_kctx(TALLOC_CTX *mem_ctx,
          struct resp_ctx *rctx)
{
    struct kcm_ctx *kctx;

    kctx = talloc_zero(mem_ctx, struct kcm_ctx);
    if (!kctx) {
        return NULL;
    }

    kctx->rctx = rctx;

    return kctx;
}

static int setup_kcm_queue(void **state)
{
    struct test_ctx *tctx;

    tctx = talloc_zero(NULL, struct test_ctx);
    assert_non_null(tctx);

    tctx->ev = tevent_context_init(tctx);
    assert_non_null(tctx->ev);

    tctx->rctx = mock_rctx(tctx, tctx->ev, NULL, NULL);
    assert_non_null(tctx->rctx);

    tctx->kctx = mock_kctx(tctx, tctx->rctx);
    assert_non_null(tctx->kctx);

    tctx->qctx = kcm_ops_queue_create(tctx->kctx, tctx->kctx);
    assert_non_null(tctx->qctx);

    *state = tctx;
    return 0;
}

static int teardown_kcm_queue(void **state)
{
    struct test_ctx *tctx = talloc_get_type(*state, struct test_ctx);
    talloc_free(tctx);
    return 0;
}

static void test_kcm_queue_done(struct tevent_req *req)
{
    struct test_ctx *test_ctx = tevent_req_callback_data(req,
                                                struct test_ctx);
    int req_id = INVALID_ID;

    test_ctx->error = timed_request_recv(req, &req_id);
    talloc_zfree(req);
    if (test_ctx->error != EOK) {
        test_ctx->done = true;
        return;
    }

    if (test_ctx->req_ids[test_ctx->finished_requests] != req_id) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Request %d finished, expected %d\n",
              req_id, test_ctx->req_ids[test_ctx->finished_requests]);
        test_ctx->error = EIO;
        test_ctx->done = true;
        return;
    }

    test_ctx->finished_requests++;
    if (test_ctx->finished_requests == test_ctx->num_requests) {
        test_ctx->done = true;
        return;
    }
}

/*
 * Just make sure that a single pass through the queue works
 */
static void test_kcm_queue_single(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;
    struct cli_creds client;
    static int req_ids[] = { 0 };

    client.ucred.uid = getuid();
    client.ucred.gid = getgid();

    req = timed_request_send(test_ctx,
                             test_ctx->ev,
                             test_ctx->rctx,
                             test_ctx->qctx,
                             &client, 1, 0);
    assert_non_null(req);
    tevent_req_set_callback(req, test_kcm_queue_done, test_ctx);

    test_ctx->num_requests = 1;
    test_ctx->req_ids = req_ids;

    while (test_ctx->done == false) {
        tevent_loop_once(test_ctx->ev);
    }
    assert_int_equal(test_ctx->error, EOK);
}

/*
 * Test that multiple requests from the same ID wait for one another
 */
static void test_kcm_queue_multi_same_id(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;
    struct cli_creds client;
    /* The slow request will finish first because request from
     * the same ID are serialized
     */
    static int req_ids[] = { SLOW_REQ_ID, FAST_REQ_ID };

    client.ucred.uid = getuid();
    client.ucred.gid = getgid();

    req = timed_request_send(test_ctx,
                             test_ctx->ev,
                             test_ctx->rctx,
                             test_ctx->qctx,
                             &client,
                             SLOW_REQ_DELAY,
                             SLOW_REQ_ID);
    assert_non_null(req);
    tevent_req_set_callback(req, test_kcm_queue_done, test_ctx);

    req = timed_request_send(test_ctx,
                             test_ctx->ev,
                             test_ctx->rctx,
                             test_ctx->qctx,
                             &client,
                             FAST_REQ_DELAY,
                             FAST_REQ_ID);
    assert_non_null(req);
    tevent_req_set_callback(req, test_kcm_queue_done, test_ctx);

    test_ctx->num_requests = 2;
    test_ctx->req_ids = req_ids;

    while (test_ctx->done == false) {
        tevent_loop_once(test_ctx->ev);
    }
    assert_int_equal(test_ctx->error, EOK);
}

/*
 * Test that multiple requests from different IDs don't wait for one
 * another and can run concurrently
 */
static void test_kcm_queue_multi_different_id(void **state)
{
    struct test_ctx *test_ctx = talloc_get_type(*state, struct test_ctx);
    struct tevent_req *req;
    struct cli_creds client;
    /* In this test, the fast request will finish sooner because
     * both requests are from different IDs, allowing them to run
     * concurrently
     */
    static int req_ids[] = { FAST_REQ_ID, SLOW_REQ_ID };

    client.ucred.uid = getuid();
    client.ucred.gid = getgid();

    req = timed_request_send(test_ctx,
                             test_ctx->ev,
                             test_ctx->rctx,
                             test_ctx->qctx,
                             &client,
                             SLOW_REQ_DELAY,
                             SLOW_REQ_ID);
    assert_non_null(req);
    tevent_req_set_callback(req, test_kcm_queue_done, test_ctx);

    client.ucred.uid = getuid() + 1;
    client.ucred.gid = getgid() + 1;

    req = timed_request_send(test_ctx,
                             test_ctx->ev,
                             test_ctx->rctx,
                             test_ctx->qctx,
                             &client,
                             FAST_REQ_DELAY,
                             FAST_REQ_ID);
    assert_non_null(req);
    tevent_req_set_callback(req, test_kcm_queue_done, test_ctx);

    test_ctx->num_requests = 2;
    test_ctx->req_ids = req_ids;

    while (test_ctx->done == false) {
        tevent_loop_once(test_ctx->ev);
    }
    assert_int_equal(test_ctx->error, EOK);
}

int main(int argc, const char *argv[])
{
    poptContext pc;
    int opt;
    int rv;
    struct poptOption long_options[] = {
        POPT_AUTOHELP
        SSSD_DEBUG_OPTS
        POPT_TABLEEND
    };

    const struct CMUnitTest tests[] = {
        cmocka_unit_test_setup_teardown(test_kcm_queue_single,
                                        setup_kcm_queue,
                                        teardown_kcm_queue),
        cmocka_unit_test_setup_teardown(test_kcm_queue_multi_same_id,
                                        setup_kcm_queue,
                                        teardown_kcm_queue),
        cmocka_unit_test_setup_teardown(test_kcm_queue_multi_different_id,
                                        setup_kcm_queue,
                                        teardown_kcm_queue),
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

    rv = cmocka_run_group_tests(tests, NULL, NULL);

    return rv;
}
