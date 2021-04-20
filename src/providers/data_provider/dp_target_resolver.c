/*
    SSSD

    Authors:
        Samuel Cabrero <scabrero@suse.com>

    Copyright (C) 2019 SUSE LINUX GmbH, Nuernberg, Germany.

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

#include "sbus/sbus_request.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

struct dp_resolver_handler_state {
    struct dp_resolver_data *data;
    struct dp_reply_std reply;
    const char *request_name;
};

static void dp_resolver_handler_done(struct tevent_req *subreq);

struct tevent_req *
dp_resolver_handler_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         uint32_t entry_type,
                         uint32_t filter_type,
                         const char *filter_value,
                         uint32_t cli_id)
{
    struct dp_resolver_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    DEBUG(SSSDBG_TRACE_FUNC, "Received request, flags [%d], "
          "entry type [%#x:%s], filter [%#x:%s]\n", dp_flags,
          entry_type, be_req2str(entry_type), filter_type, filter_value);

    req = tevent_req_create(mem_ctx, &state, struct dp_resolver_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_resolver_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->data->filter_type = filter_type;
    state->data->filter_value = filter_value;

    switch (entry_type) {
    case BE_REQ_HOST:
        subreq = dp_req_send(state, provider, NULL, "Resolver", cli_id,
                             sbus_req->sender->name, DPT_RESOLVER,
                             DPM_RESOLVER_HOSTS_HANDLER, dp_flags,
                             state->data, &state->request_name);
        break;
    case BE_REQ_IP_NETWORK:
        subreq = dp_req_send(state, provider, NULL, "Resolver", cli_id,
                             sbus_req->sender->name, DPT_RESOLVER,
                             DPM_RESOLVER_IP_NETWORK_HANDLER, dp_flags,
                             state->data, &state->request_name);
        break;
    default:
        ret = EINVAL;
        goto done;
    }

    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_resolver_handler_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_resolver_handler_done(struct tevent_req *subreq)
{
    struct dp_resolver_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_resolver_handler_state);

    ret = dp_req_recv(state, subreq, struct dp_reply_std, &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t
dp_resolver_handler_recv(TALLOC_CTX *mem_ctx,
                         struct tevent_req *req,
                         uint16_t *_dp_error,
                         uint32_t *_error,
                         const char **_err_msg)
{
    struct dp_resolver_handler_state *state;
    state = tevent_req_data(req, struct dp_resolver_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    dp_req_reply_std(state->request_name, &state->reply,
                     _dp_error, _error, _err_msg);

    return EOK;
}
