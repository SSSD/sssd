/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include <talloc.h>
#include <tevent.h>
#include <errno.h>
#include <popt.h>
#include <time.h>

#include "providers/backend.h"
#include "providers/be_ptask_private.h"
#include "providers/be_ptask.h"
#include "tests/cmocka/common_mock.h"
#include "tests/cmocka/common_mock_be.h"
#include "tests/common.h"

#define DELAY  2
#define PERIOD 1
#define TIMEOUT 123

#define new_test(test) \
    cmocka_unit_test_setup_teardown(test_ ## test, test_setup, test_teardown)

struct test_ctx {
    struct sss_test_ctx *tctx;
    struct be_ctx *be_ctx;

    time_t when;
    bool done;

    bool add_online_cb_called;
    bool add_offline_cb_called;
};

#define mark_online(test_ctx) do { \
    test_ctx->be_ctx->offline = false; \
} while (0)

#define mark_offline(test_ctx) do { \
    test_ctx->be_ctx->offline = true; \
} while (0)

/* Since both test_ctx->done and ptask->req is marked as finished already
 * in the sync _send function before a new execution is scheduled we need to
 * rely on the fact that ptask->req is set to zero when a new timer is
 * created. This way we guarantee that the condition is true only when
 * the ptask is executed and a new one is scheduled. */
#define is_sync_ptask_finished(test_ctx, ptask) \
    (test_ctx->done && ptask->req == NULL)

static time_t get_current_time(void)
{
    struct timeval tv;
    int ret;

    ret = gettimeofday(&tv, NULL);
    assert_int_equal(0, ret);
    return tv.tv_sec;
}

/* Mock few backend functions so we don't have to bring the whole
 * data provider into this test. */

bool be_is_offline(struct be_ctx *ctx)
{
    return ctx->offline;
}

int be_add_online_cb(TALLOC_CTX *mem_ctx,
                     struct be_ctx *ctx,
                     be_callback_t cb,
                     void *pvt,
                     struct be_cb **online_cb)
{
    struct test_ctx *test_ctx = NULL;

    test_ctx = sss_mock_ptr_type(struct test_ctx *);
    test_ctx->add_online_cb_called = true;

    return ERR_OK;
}

int be_add_offline_cb(TALLOC_CTX *mem_ctx,
                      struct be_ctx *ctx,
                      be_callback_t cb,
                      void *pvt,
                      struct be_cb **offline_cb)
{
    struct test_ctx *test_ctx = NULL;

    test_ctx = sss_mock_ptr_type(struct test_ctx *);
    test_ctx->add_offline_cb_called = true;

    return ERR_OK;
}

struct test_be_ptask_state {
    struct test_ctx *test_ctx;
};

struct tevent_req * test_be_ptask_send(TALLOC_CTX *mem_ctx,
                                       struct tevent_context *ev,
                                       struct be_ctx *be_ctx,
                                       struct be_ptask *be_ptask,
                                       void *pvt)
{
    struct test_be_ptask_state *state = NULL;
    struct test_ctx *test_ctx = NULL;
    struct tevent_req *req = NULL;

    assert_non_null(ev);
    assert_non_null(be_ctx);
    assert_non_null(be_ptask);
    assert_non_null(pvt);

    test_ctx = talloc_get_type(pvt, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->when = get_current_time();

    req = tevent_req_create(mem_ctx, &state, struct test_be_ptask_state);
    assert_non_null(req);

    state->test_ctx = test_ctx;

    tevent_req_done(req);
    tevent_req_post(req, ev);
    return req;
}

struct tevent_req * test_be_ptask_null_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_ctx *be_ctx,
                                            struct be_ptask *be_ptask,
                                            void *pvt)
{
    struct test_ctx *test_ctx = NULL;
    assert_non_null(ev);
    assert_non_null(be_ctx);
    assert_non_null(be_ptask);
    assert_non_null(pvt);

    test_ctx = talloc_get_type(pvt, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->when = get_current_time();
    test_ctx->done = true;

    return NULL;
}

struct tevent_req * test_be_ptask_timeout_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct be_ctx *be_ctx,
                                               struct be_ptask *be_ptask,
                                               void *pvt)
{
    struct test_be_ptask_state *state = NULL;
    struct test_ctx *test_ctx = NULL;
    struct tevent_req *req = NULL;

    assert_non_null(ev);
    assert_non_null(be_ctx);
    assert_non_null(be_ptask);
    assert_non_null(pvt);

    test_ctx = talloc_get_type(pvt, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->when = get_current_time();

    req = tevent_req_create(mem_ctx, &state, struct test_be_ptask_state);
    assert_non_null(req);

    state->test_ctx = test_ctx;

    /* we won't finish the request */

    return req;
}

errno_t test_be_ptask_recv(struct tevent_req *req)
{
    struct test_be_ptask_state *state = NULL;

    state = tevent_req_data(req, struct test_be_ptask_state);
    assert_non_null(state);

    state->test_ctx->done = true;

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return ERR_OK;
}

errno_t test_be_ptask_error_recv(struct tevent_req *req)
{
    struct test_be_ptask_state *state = NULL;

    state = tevent_req_data(req, struct test_be_ptask_state);
    assert_non_null(state);

    state->test_ctx->done = true;

    return ERR_INTERNAL;
}

errno_t test_be_ptask_sync(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct be_ctx *be_ctx,
                           struct be_ptask *be_ptask,
                           void *pvt)
{
    struct test_ctx *test_ctx = NULL;

    assert_non_null(ev);
    assert_non_null(be_ctx);
    assert_non_null(be_ptask);
    assert_non_null(pvt);

    test_ctx = talloc_get_type(pvt, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->when = get_current_time();
    test_ctx->done = true;

    return ERR_OK;
}

errno_t test_be_ptask_sync_error(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct be_ctx *be_ctx,
                                 struct be_ptask *be_ptask,
                                 void *pvt)
{
    struct test_ctx *test_ctx = NULL;

    assert_non_null(ev);
    assert_non_null(be_ctx);
    assert_non_null(be_ptask);
    assert_non_null(pvt);

    test_ctx = talloc_get_type(pvt, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->when = get_current_time();
    test_ctx->done = true;

    return ERR_INTERNAL;
}

static int test_setup(void **state)
{
    struct test_ctx *test_ctx = NULL;

    assert_true(leak_check_setup());

    test_ctx = talloc_zero(global_talloc_context, struct test_ctx);
    assert_non_null(test_ctx);

    test_ctx->tctx = create_ev_test_ctx(test_ctx);
    assert_non_null(test_ctx->tctx);

    test_ctx->be_ctx = mock_be_ctx(test_ctx, test_ctx->tctx);
    assert_non_null(test_ctx->be_ctx);

    test_ctx->be_ctx->ev = tevent_context_init(test_ctx->be_ctx);
    assert_non_null(test_ctx->be_ctx->ev);

    check_leaks_push(test_ctx);
    *state = test_ctx;
    return 0;
}

static int test_teardown(void **state)
{
    assert_true(check_leaks_pop(*state));
    talloc_zfree(*state);
    assert_true(leak_check_teardown());
    return 0;
}

void test_be_ptask_create_einval_be(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, NULL, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_create_einval_period(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, 0, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_create_einval_send(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, NULL,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_create_einval_recv(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          NULL, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_create_einval_name(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, NULL,
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_mixed_from_flags_einval(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP |
                          BE_PTASK_SCHEDULE_FROM_LAST |
                          BE_PTASK_SCHEDULE_FROM_NOW,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_no_from_flags_einval(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}
void test_be_ptask_mixed_offline_flags_einval(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP |
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_NOW,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}
void test_be_ptask_no_offline_flags_einval(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, NULL, "Test ptask",
                          BE_PTASK_SCHEDULE_FROM_NOW,
                          &ptask);
    assert_int_equal(ret, EINVAL);
    assert_null(ptask);
}

void test_be_ptask_create_no_delay(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now <= ptask->last_execution);
    assert_true(now <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_create_first_delay(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, DELAY, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now + DELAY <= ptask->last_execution);
    assert_true(now + DELAY <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_disable(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    be_ptask_disable(ptask);

    assert_null(ptask->timer);
    assert_false(ptask->enabled);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_enable(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    be_ptask_disable(ptask);

    now = get_current_time();
    be_ptask_enable(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now <= ptask->last_execution);
    assert_true(now <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_enable_delay(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, DELAY, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    be_ptask_disable(ptask);
    test_ctx->done = false;
    now = get_current_time();
    be_ptask_enable(ptask);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now + DELAY <= ptask->last_execution);
    assert_true(now + DELAY <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_postpone(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, 30, 10, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);
    assert_true(now + 10 <= ptask->next_execution);
    assert_true(now + 30 > ptask->next_execution);

    be_ptask_postpone(ptask);
    assert_true(now + 30 <= ptask->next_execution);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_offline_skip(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t next_execution;
    time_t now;
    errno_t ret;

    mark_offline(test_ctx);

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    next_execution = ptask->next_execution;
    assert_true(now <= next_execution);

    while (ptask->next_execution == next_execution && !test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(next_execution + PERIOD <= ptask->next_execution);
    assert_true(ptask->enabled);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_offline_disable(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    mark_offline(test_ctx);

    will_return(be_add_online_cb, test_ctx);
    will_return(be_add_offline_cb, test_ctx);

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    assert_true(test_ctx->add_online_cb_called);
    assert_true(test_ctx->add_offline_cb_called);

    while (ptask->enabled && !test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_false(ptask->enabled);
    assert_false(test_ctx->done);
    assert_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_offline_execute(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    mark_offline(test_ctx);

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_EXECUTE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(ptask->enabled);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_reschedule_ok(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t next_execution;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    next_execution = ptask->next_execution;

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now <= ptask->last_execution);
    assert_true(now <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_reschedule_null(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now = 0;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_null_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        now = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_reschedule_error(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now = 0;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_error_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        now = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_reschedule_timeout(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now = 0;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 1,
                          0, test_be_ptask_timeout_send,
                          test_be_ptask_error_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    /* first iterate until the task is executed */
    while (!test_ctx->done && ptask->req == NULL) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    /* then iterate until the request is destroyed */
    while (!test_ctx->done && ptask->req != NULL) {
        now = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_false(test_ctx->done);
    assert_true(now + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_reschedule_backoff(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t next_execution;
    time_t now_first;
    time_t now_backoff = 0;
    errno_t ret;

    now_first = get_current_time();
    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          PERIOD*2, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    /* first run */
    next_execution = ptask->next_execution;

    while (!test_ctx->done) {
        /* We need to acquire timestamp for the second test here, since this
         * is the closest value to the timestamp when the next event is
         * scheduled. */
        now_backoff = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now_first <= ptask->last_execution);
    assert_true(now_first <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD <= ptask->next_execution);
    assert_int_equal(PERIOD*2, ptask->period);
    assert_non_null(ptask->timer);

    test_ctx->done = false;

    /* second run */
    next_execution = ptask->next_execution;

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now_backoff + PERIOD <= ptask->last_execution);
    assert_true(now_backoff + PERIOD <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD*2 <= ptask->next_execution);
    assert_int_equal(PERIOD*2, ptask->period);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_get_period(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t out_period;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);

    out_period = be_ptask_get_period(ptask);
    assert_true(PERIOD == out_period);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_get_timeout(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t out_timeout;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, TIMEOUT,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_SKIP | BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);

    out_timeout = be_ptask_get_timeout(ptask);
    assert_true(TIMEOUT == out_timeout);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_running(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    mark_offline(test_ctx);

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_OFFLINE_EXECUTE |
                          BE_PTASK_SCHEDULE_FROM_NOW,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);
    assert_true(ptask->enabled);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
        if (ptask->req != NULL) {
            break;
        }
    }

    assert_true(be_ptask_running(ptask));
    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_no_periodic(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    errno_t ret;

    ret = be_ptask_create(test_ctx, test_ctx->be_ctx, 0, 0, DELAY, 0, 0,
                          0, test_be_ptask_send,
                          test_be_ptask_recv, test_ctx, "Test ptask",
                          BE_PTASK_NO_PERIODIC |
                          BE_PTASK_OFFLINE_SKIP |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_create_sync(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create_sync(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                               0, test_be_ptask_sync, test_ctx, "Test ptask",
                               BE_PTASK_OFFLINE_SKIP, &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!test_ctx->done) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now <= ptask->last_execution);
    assert_true(now <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_sync_reschedule_ok(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t next_execution;
    time_t now;
    errno_t ret;

    now = get_current_time();
    ret = be_ptask_create_sync(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                               0, test_be_ptask_sync, test_ctx, "Test ptask",
                               BE_PTASK_OFFLINE_SKIP, &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    next_execution = ptask->next_execution;

    while (!is_sync_ptask_finished(test_ctx, ptask)) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now <= ptask->last_execution);
    assert_true(now <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_sync_reschedule_error(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t now = 0;
    errno_t ret;

    ret = be_ptask_create_sync(test_ctx, test_ctx->be_ctx, PERIOD, 0, 0, 0, 0,
                               0, test_be_ptask_sync_error,
                               test_ctx, "Test ptask",
                               BE_PTASK_OFFLINE_SKIP, &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    while (!is_sync_ptask_finished(test_ctx, ptask)) {
        now = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now + PERIOD <= ptask->next_execution);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
}

void test_be_ptask_sync_reschedule_backoff(void **state)
{
    struct test_ctx *test_ctx = (struct test_ctx *)(*state);
    struct be_ptask *ptask = NULL;
    time_t next_execution;
    time_t now_first;
    time_t now_backoff = 0;
    errno_t ret;

    now_first = get_current_time();
    ret = be_ptask_create_sync(test_ctx, test_ctx->be_ctx, PERIOD,
                               0, 0, 0, 0, PERIOD*2,
                               test_be_ptask_sync_error,
                               test_ctx, "Test ptask",
                               BE_PTASK_OFFLINE_SKIP, &ptask);
    assert_int_equal(ret, ERR_OK);
    assert_non_null(ptask);
    assert_non_null(ptask->timer);

    /* first run */
    next_execution = ptask->next_execution;

    while (!is_sync_ptask_finished(test_ctx, ptask)) {
        /* We need to acquire timestamp for the second test here, since this
         * is the closest value to the timestamp when the next event is
         * scheduled. */
        now_backoff = get_current_time();
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now_first <= ptask->last_execution);
    assert_true(now_first <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD <= ptask->next_execution);
    assert_int_equal(PERIOD*2, ptask->period);
    assert_non_null(ptask->timer);

    test_ctx->done = false;

    /* second run */
    next_execution = ptask->next_execution;

    while (!is_sync_ptask_finished(test_ctx, ptask)) {
        tevent_loop_once(test_ctx->be_ctx->ev);
    }

    assert_true(now_backoff + PERIOD <= ptask->last_execution);
    assert_true(now_backoff + PERIOD <= test_ctx->when);
    assert_true(ptask->last_execution <= test_ctx->when);

    assert_true(next_execution + PERIOD*2 <= ptask->next_execution);
    assert_int_equal(PERIOD*2, ptask->period);
    assert_non_null(ptask->timer);

    be_ptask_destroy(&ptask);
    assert_null(ptask);
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
        new_test(be_ptask_create_einval_be),
        new_test(be_ptask_create_einval_period),
        new_test(be_ptask_create_einval_send),
        new_test(be_ptask_create_einval_recv),
        new_test(be_ptask_create_einval_name),
        new_test(be_ptask_mixed_from_flags_einval),
        new_test(be_ptask_no_from_flags_einval),
        new_test(be_ptask_mixed_offline_flags_einval),
        new_test(be_ptask_no_offline_flags_einval),
        new_test(be_ptask_create_no_delay),
        new_test(be_ptask_create_first_delay),
        new_test(be_ptask_disable),
        new_test(be_ptask_enable),
        new_test(be_ptask_enable_delay),
        new_test(be_ptask_postpone),
        new_test(be_ptask_offline_skip),
        new_test(be_ptask_offline_disable),
        new_test(be_ptask_offline_execute),
        new_test(be_ptask_reschedule_ok),
        new_test(be_ptask_reschedule_null),
        new_test(be_ptask_reschedule_error),
        new_test(be_ptask_reschedule_timeout),
        new_test(be_ptask_reschedule_backoff),
        new_test(be_ptask_get_period),
        new_test(be_ptask_get_timeout),
        new_test(be_ptask_running),
        new_test(be_ptask_no_periodic),
        new_test(be_ptask_create_sync),
        new_test(be_ptask_sync_reschedule_ok),
        new_test(be_ptask_sync_reschedule_error),
        new_test(be_ptask_sync_reschedule_backoff)
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

    return cmocka_run_group_tests(tests, NULL, NULL);
}
