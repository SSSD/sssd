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

#include "providers/ad/ad_common.h"
#include "providers/ad/ad_id.h"

struct ad_refresh_state {
    struct tevent_context *ev;
    struct be_ctx *be_ctx;
    struct dp_id_data *account_req;
    struct ad_id_ctx *id_ctx;
    struct sss_domain_info *domain;
    char **names;
    size_t index;
};

static errno_t ad_refresh_step(struct tevent_req *req);
static void ad_refresh_done(struct tevent_req *subreq);

static struct tevent_req *ad_refresh_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct be_ctx *be_ctx,
                                            struct sss_domain_info *domain,
                                            int entry_type,
                                            char **names,
                                            void *pvt)
{
    struct ad_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;
    uint32_t filter_type;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_refresh_state);
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
    state->id_ctx = talloc_get_type(pvt, struct ad_id_ctx);
    state->names = names;
    state->index = 0;

    switch (entry_type) {
    case BE_REQ_INITGROUPS:
    case BE_REQ_NETGROUP:
        filter_type = BE_FILTER_NAME;
        break;
    case BE_REQ_USER:
    case BE_REQ_GROUP:
        filter_type = BE_FILTER_SECID;
        break;
    default:
        ret = EINVAL;
        goto immediately;
    }

    state->account_req = be_refresh_acct_req(state, entry_type,
                                             filter_type, domain);
    if (state->account_req == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    ret = ad_refresh_step(req);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_FUNC, "Nothing to refresh\n");
        goto immediately;
    } else if (ret != EAGAIN) {
        DEBUG(SSSDBG_CRIT_FAILURE, "ad_refresh_step() failed "
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

static errno_t ad_refresh_step(struct tevent_req *req)
{
    struct ad_refresh_state *state = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    state = tevent_req_data(req, struct ad_refresh_state);

    if (state->names == NULL) {
        ret = EOK;
        goto done;
    }

    state->account_req->filter_value = state->names[state->index];
    if (state->account_req->filter_value == NULL) {
        ret = EOK;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing refresh of %s %s\n",
          be_req2str(state->account_req->entry_type),
          state->account_req->filter_value);

    subreq = ad_account_info_send(state, state->be_ctx, state->id_ctx,
                                  state->account_req);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, ad_refresh_done, req);

    state->index++;
    ret = EAGAIN;

done:
    return ret;
}

static void ad_refresh_done(struct tevent_req *subreq)
{
    struct ad_refresh_state *state = NULL;
    struct tevent_req *req = NULL;
    const char *err_msg = NULL;
    errno_t dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_refresh_state);

    ret = ad_account_info_recv(subreq, &dp_error, &err_msg);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to refresh %s [dp_error: %d, "
              "errno: %d]: %s\n", be_req2str(state->account_req->entry_type),
              dp_error, ret, err_msg);
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

    ret = ad_refresh_step(req);
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

static errno_t ad_refresh_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

REFRESH_SEND_RECV_FNS(ad_refresh_initgroups, ad_refresh, BE_REQ_INITGROUPS);
REFRESH_SEND_RECV_FNS(ad_refresh_users, ad_refresh, BE_REQ_USER);
REFRESH_SEND_RECV_FNS(ad_refresh_groups, ad_refresh, BE_REQ_GROUP);
REFRESH_SEND_RECV_FNS(ad_refresh_netgroups, ad_refresh, BE_REQ_NETGROUP);

errno_t ad_refresh_init(struct be_ctx *be_ctx,
                        struct ad_id_ctx *id_ctx)
{
    errno_t ret;
    struct be_refresh_cb ad_refresh_callbacks[] = {
        { .send_fn = ad_refresh_initgroups_send,
          .recv_fn = ad_refresh_initgroups_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ad_refresh_users_send,
          .recv_fn = ad_refresh_users_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ad_refresh_groups_send,
          .recv_fn = ad_refresh_groups_recv,
          .pvt = id_ctx,
        },
        { .send_fn = ad_refresh_netgroups_send,
          .recv_fn = ad_refresh_netgroups_recv,
          .pvt = id_ctx,
        },
    };

    ret = be_refresh_ctx_init_with_callbacks(be_ctx,
                                             SYSDB_SID_STR,
                                             ad_refresh_callbacks);
    if (ret != EOK) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Unable to initialize background refresh\n");
        return ret;
    }

    return ret;
}
