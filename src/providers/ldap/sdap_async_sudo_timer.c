/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2011 Red Hat

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

#include <errno.h>
#include <tevent.h>
#include <talloc.h>

#include "util/util.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_id_op.h"
#include "providers/ldap/sdap_sudo.h"

struct sdap_sudo_timer_state {
    struct tevent_context *ev;
    struct sdap_sudo_ctx *sudo_ctx;
    time_t timeout;          /* relative time how many seconds wait before
                                canceling fn request */
    sdap_sudo_timer_fn_t fn; /* request executed on 'when' */

    struct tevent_req *subreq;
    struct tevent_timer *timer_timeout;
};

static void sdap_sudo_timer(struct tevent_context *ev,
                            struct tevent_timer *tt,
                            struct timeval tv, void *pvt);

static void sdap_sudo_timer_done(struct tevent_req *subreq);

static void sdap_sudo_timer_timeout(struct tevent_context *ev,
                                    struct tevent_timer *tt,
                                    struct timeval tv, void *pvt);

struct tevent_req * sdap_sudo_timer_send(TALLOC_CTX *mem_ctx,
                                         struct tevent_context *ev,
                                         struct sdap_sudo_ctx *sudo_ctx,
                                         struct timeval when,
                                         time_t timeout,
                                         sdap_sudo_timer_fn_t fn)
{
    struct tevent_req *req = NULL;
    struct tevent_timer *timer = NULL;
    struct sdap_sudo_timer_state *state = NULL;
    int ret;

    /* create request */
    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_timer_state);
    if (req == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("tevent_req_create() failed\n"));
        return NULL;
    }

    state->ev = ev;
    state->sudo_ctx = sudo_ctx;
    state->timeout = timeout;
    state->fn = fn;

    /* set timer */
    timer = tevent_add_timer(ev, req, when, sdap_sudo_timer, req);
    if (timer == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, ("tevent_add_timer() failed\n"));
        ret = ENOMEM;
        goto immediately;
    }

    return req;

immediately:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);

    return req;
}

int sdap_sudo_timer_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         struct tevent_req **_subreq)
{
    struct sdap_sudo_timer_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_timer_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    *_subreq = talloc_steal(mem_ctx, state->subreq);

    return EOK;
}

static void sdap_sudo_timer(struct tevent_context *ev,
                            struct tevent_timer *tt,
                            struct timeval tv, void *pvt)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_timer_state *state = NULL;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_timer_state);

    /* issue request */
    state->subreq = state->fn(state, state->sudo_ctx);
    if (state->subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, ("Unable to issue timed request!\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }

    tevent_req_set_callback(state->subreq, sdap_sudo_timer_done, req);

    /* schedule timeout */
    tv = tevent_timeval_current_ofs(state->timeout, 0);
    state->timer_timeout = tevent_add_timer(state->ev, state->subreq, tv,
                                            sdap_sudo_timer_timeout, req);
    if (state->timer_timeout == NULL) {
        /* If we can't guarantee a timeout, we
         * need to cancel the request, to avoid
         * the possibility of starting another
         * concurrently
         */
        DEBUG(SSSDBG_CRIT_FAILURE, ("Failed to set timeout, "
                                    "canceling request!\n"));
        talloc_zfree(state->subreq);
        tevent_req_error(req, ENOMEM);
    }
}

static void sdap_sudo_timer_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_timer_state *state = NULL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    /* do not free subreq, it is returned in recv */

    /* cancel timeout */
    state = tevent_req_data(req, struct sdap_sudo_timer_state);
    talloc_zfree(state->timer_timeout);

    tevent_req_done(req);
}

static void sdap_sudo_timer_timeout(struct tevent_context *ev,
                                    struct tevent_timer *tt,
                                    struct timeval tv, void *pvt)
{
    struct tevent_req *req = NULL;
    struct sdap_sudo_timer_state *state = NULL;

    req = talloc_get_type(pvt, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_timer_state);

    DEBUG(SSSDBG_CRIT_FAILURE, ("Request timed out. Is timeout too small?"
                                " (%ds)!\n", state->timeout));

    talloc_zfree(state->subreq);

    tevent_req_error(req, EAGAIN);
}
