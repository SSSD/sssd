/*
    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

    SSSD tests: Common utilities for tests that exercise domains

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

#include <tevent.h>
#include <talloc.h>
#include <errno.h>

#include "tests/common.h"

struct sss_test_ctx *
create_ev_test_ctx(TALLOC_CTX *mem_ctx)
{
    struct sss_test_ctx *test_ctx;

    test_ctx = talloc_zero(mem_ctx, struct sss_test_ctx);
    if (test_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_zero failed\n");
        goto fail;
    }

    /* Create an event context */
    test_ctx->ev = tevent_context_init(test_ctx);
    if (test_ctx->ev == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_context_init failed\n");
        goto fail;
    }

    return test_ctx;

fail:
    talloc_free(test_ctx);
    return NULL;
}

struct tevent_req *
test_request_send(TALLOC_CTX *mem_ctx, struct tevent_context *ev, errno_t err)
{
    struct tevent_req *req;
    int *state;

    req = tevent_req_create(mem_ctx, &state, int);
    if (!req) return NULL;

    if (err == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, err);
    }
    tevent_req_post(req, ev);
    return req;
}

errno_t test_request_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

int test_ev_loop(struct sss_test_ctx *tctx)
{
    while (!tctx->done)
        tevent_loop_once(tctx->ev);

    return tctx->error;
}

void test_ev_done(struct sss_test_ctx *tctx, errno_t ret)
{
    tctx->error = ret;
    tctx->done = true;
}
