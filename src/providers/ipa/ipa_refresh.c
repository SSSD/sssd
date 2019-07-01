/*
    Copyright (C) 2019 Red Hat

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

#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_id.h"

struct ipa_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct dp_id_data *account_req;
    struct ipa_id_ctx *id_ctx;
    struct sss_domain_info *domain;
    char **names;
    size_t index;
};

static errno_t ipa_refresh_step(struct tevent_req *req);
static void ipa_refresh_done(struct tevent_req *subreq);

static struct tevent_req *ipa_refresh_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_ctx *be_ctx,
                                            struct sss_domain_info *domain,
                                            int entry_type,
                                            char **names,
                                            void *pvt)
{
    struct ipa_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (names == NULL) {
        ret = EOK;
        goto immediately;
    }

    state->ev = ev;
    state->be_ctx = be_ctx;
    state->domain = domain;
    state->id_ctx = talloc_get_type(pvt, struct ipa_id_ctx);
    state->names = names;
    state->index = 0;

    state->account_req = be_refresh_acct_req(state, entry_type,
                                             BE_FILTER_NAME, domain);
    if (state->account_req == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = ipa_refresh_step(req);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Nothing to refresh\n");
        goto immediately;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ipa_refresh_step() failed "
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

static errno_t ipa_refresh_step(struct tevent_req *req)
{
    struct ipa_refresh_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct ipa_refresh_state);

    if (state->names == NULL) {
        ret = EOK;
        goto done;
    }

    state->account_req->filter_value = state->names[state->index];
    if (state->account_req->filter_value == NULL) {
        ret = EOK;
        goto done;
    }

    subreq = ipa_account_info_send(state, state->be_ctx, state->id_ctx,
                                  state->account_req);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_refresh_done, req);

    state->index++;
    ret = EAGAIN;

done:
    return ret;
}

static void ipa_refresh_done(struct tevent_req *subreq)
{
    struct ipa_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_refresh_state);

    ret = ipa_account_info_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh %s [dp_error: %d, "
              "errno: %d]\n", be_req2str(state->account_req->entry_type),
              dp_error, ret);
        goto done;
    }

    if (state->account_req->entry_type == BE_REQ_INITGROUPS) {
        ret = sysdb_set_initgr_expire_timestamp(state->domain,
                                                state->account_req->filter_value);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Failed to set initgroups expiration for [%s]\n",
                  state->account_req->filter_value);
        }
    }

    ret = ipa_refresh_step(req);
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

static errno_t ipa_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

REFRESH_SEND_RECV_FNS(ipa_refresh_initgroups, ipa_refresh, BE_REQ_INITGROUPS);
REFRESH_SEND_RECV_FNS(ipa_refresh_users, ipa_refresh, BE_REQ_USER);
REFRESH_SEND_RECV_FNS(ipa_refresh_groups, ipa_refresh, BE_REQ_GROUP);
REFRESH_SEND_RECV_FNS(ipa_refresh_netgroups, ipa_refresh, BE_REQ_NETGROUP);

errno_t ipa_refresh_init(struct be_ctx *be_ctx,
                         struct ipa_id_ctx *id_ctx)
{
    errno_t ret;
    struct be_refresh_cb ipa_refresh_callbacks[] = {
        { .send_fn = ipa_refresh_initgroups_send,
          .recv_fn = ipa_refresh_initgroups_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ipa_refresh_users_send,
          .recv_fn = ipa_refresh_users_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ipa_refresh_groups_send,
          .recv_fn = ipa_refresh_groups_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ipa_refresh_netgroups_send,
          .recv_fn = ipa_refresh_netgroups_recv,
          .pvt = id_ctx,
        },
    };

    ret = be_refresh_ctx_init_with_callbacks(be_ctx,
                                             SYSDB_NAME,
                                             ipa_refresh_callbacks);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize background refresh\n");
        return ret;
    }

    return EOK;
}
