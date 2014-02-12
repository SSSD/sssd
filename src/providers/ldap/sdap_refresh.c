/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2013 Red Hat

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

#include "providers/ldap/sdap.h"
#include "providers/ldap/ldap_common.h"

struct sdap_refresh_netgroups_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *id_ctx;
    char **names;
    size_t index;
};

static errno_t sdap_refresh_netgroups_step(struct tevent_req *req);
static void sdap_refresh_netgroups_done(struct tevent_req *subreq);

struct tevent_req *sdap_refresh_netgroups_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct be_ctx *be_ctx,
                                               char **names,
                                               void *pvt)
{
    struct sdap_refresh_netgroups_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct sdap_refresh_netgroups_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->ev = ev;
    state->id_ctx = talloc_get_type(pvt, struct sdap_id_ctx);
    state->names = names;
    state->index = 0;

    if (names == NULL) {
        ret = EOK;
        goto immediately;
    }

    ret = sdap_refresh_netgroups_step(req);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Nothing to refresh\n");
        goto immediately;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap_refresh_netgroups_step() failed "
                                    "[%d]: %s\n", ret, sss_strerror(ret));
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

static errno_t sdap_refresh_netgroups_step(struct tevent_req *req)
{
    struct sdap_refresh_netgroups_state *state = NULL;
    struct tevent_req *subreq = NULL;
    const char *name = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct sdap_refresh_netgroups_state);

    if (state->names == NULL) {
        ret = EOK;
        goto done;
    }

    name = state->names[state->index];
    if (name == NULL) {
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing refresh of netgroup %s\n", name);

    subreq = ldap_netgroup_get_send(state, state->ev, state->id_ctx,
                                    state->id_ctx->opts->sdom,
                                    state->id_ctx->conn,
                                    name, true);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, sdap_refresh_netgroups_done, req);

    state->index++;
    ret = EAGAIN;

done:
    return ret;
}

static void sdap_refresh_netgroups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = NULL;
    errno_t dp_error;
    int sdap_ret;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = ldap_netgroup_get_recv(subreq, &dp_error, &sdap_ret);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh netgroup [dp_error: %d, "
              "sdap_ret: %d, errno: %d]: %s\n",
              dp_error, sdap_ret, ret, sss_strerror(ret));
        goto done;
    }

    ret = sdap_refresh_netgroups_step(req);
    if (ret == EAGAIN) {
        return;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t sdap_refresh_netgroups_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
