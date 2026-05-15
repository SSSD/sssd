/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2016 Red Hat

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

struct dp_autofs_get_map_state {
    struct dp_autofs_data *data;
};

static void dp_autofs_get_map_done(struct tevent_req *subreq);

struct tevent_req *
dp_autofs_get_map_send(TALLOC_CTX *mem_ctx,
                       struct tevent_context *ev,
                       struct sbus_request *sbus_req,
                       struct data_provider *provider,
                       uint32_t dp_flags,
                       const char *mapname,
                       uint32_t cli_id)
{
    struct dp_autofs_get_map_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_autofs_get_map_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_autofs_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->data->mapname = mapname;

    subreq = dp_req_send(state, provider, NULL, "AutoFS", cli_id,
                         sbus_req->sender->name, DPT_AUTOFS, DPM_AUTOFS_GET_MAP,
                         dp_flags, state->data, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_autofs_get_map_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_autofs_get_map_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = dp_req_recv_no_output(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t dp_autofs_get_map_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct dp_autofs_get_entry_state {
    struct dp_autofs_data *data;
};

static void dp_autofs_get_entry_done(struct tevent_req *subreq);

struct tevent_req *
dp_autofs_get_entry_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         const char *mapname,
                         const char *entryname,
                         uint32_t cli_id)
{
    struct dp_autofs_get_entry_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_autofs_get_entry_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_autofs_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->data->mapname = mapname;
    state->data->entryname = entryname;

    subreq = dp_req_send(state, provider, NULL, "AutoFS", cli_id,
                         sbus_req->sender->name, DPT_AUTOFS,
                         DPM_AUTOFS_GET_ENTRY, dp_flags, state->data,
                         NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_autofs_get_entry_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_autofs_get_entry_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = dp_req_recv_no_output(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t dp_autofs_get_entry_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct dp_autofs_enumerate_state {
    struct dp_autofs_data *data;
};

static void dp_autofs_enumerate_done(struct tevent_req *subreq);

struct tevent_req *
dp_autofs_enumerate_send(TALLOC_CTX *mem_ctx,
                         struct tevent_context *ev,
                         struct sbus_request *sbus_req,
                         struct data_provider *provider,
                         uint32_t dp_flags,
                         const char *mapname,
                         uint32_t cli_id)
{
    struct dp_autofs_enumerate_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_autofs_enumerate_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_autofs_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    state->data->mapname = mapname;

    subreq = dp_req_send(state, provider, NULL, "AutoFS", cli_id,
                         sbus_req->sender->name, DPT_AUTOFS,
                         DPM_AUTOFS_ENUMERATE, dp_flags, state->data,
                         NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_autofs_enumerate_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_autofs_enumerate_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    ret = dp_req_recv_no_output(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

errno_t dp_autofs_enumerate_recv(TALLOC_CTX *mem_ctx, struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
