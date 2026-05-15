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
#include "sbus/interface/sbus_iterator_readers.h"
#include "providers/data_provider/dp_private.h"
#include "providers/data_provider/dp_iface.h"
#include "providers/backend.h"
#include "util/util.h"

static errno_t dp_sudo_parse_message(TALLOC_CTX *mem_ctx,
                                     DBusMessageIter *read_iter,
                                     uint32_t *_dp_flags,
                                     uint32_t *_sudo_type,
                                     const char ***_rules)
{
    uint32_t dp_flags;
    uint32_t sudo_type;
    uint32_t num_rules;
    const char **rules;
    errno_t ret;

    ret = sbus_iterator_read_u(read_iter, &dp_flags);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse the message (flags)!\n");
        return ret;
    }

    ret = sbus_iterator_read_u(read_iter, &sudo_type);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to parse the message (type)!\n");
        return ret;
    }

    /* get additional arguments according to the request type */
    switch (sudo_type) {
    case BE_REQ_SUDO_FULL:
        /* no arguments required */
        rules = NULL;
        break;
    case BE_REQ_SUDO_RULES:
        /* additional arguments:
         * rules_num
         * rules[rules_num]
         */
        /* read rules_num */
        ret = sbus_iterator_read_u(read_iter, &num_rules);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to parse the message (num rules)!\n");
            return ret;
        }

        ret = sbus_iterator_read_as(mem_ctx, read_iter, &rules);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Failed to parse the message (rules)!\n");
            return ret;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type %d\n", sudo_type);
        return EINVAL;
    }

    *_dp_flags = dp_flags;
    *_sudo_type = sudo_type;
    *_rules = rules;

    return EOK;
}

static const char *dp_sudo_get_name(uint32_t type)
{
    switch (type) {
    case BE_REQ_SUDO_FULL:
        return "SUDO Full Refresh";
    case BE_REQ_SUDO_RULES:
        return "SUDO Rules Refresh";
    }

    return NULL;
}

struct dp_sudo_handler_state {
    struct dp_sudo_data *data;
    struct dp_reply_std reply;
    const char *request_name;
};

static void dp_sudo_handler_done(struct tevent_req *subreq);

struct tevent_req *
dp_sudo_handler_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct sbus_request *sbus_req,
                     struct data_provider *provider,
                     DBusMessageIter *read_iter)
{
    struct dp_sudo_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    uint32_t dp_flags;
    const char *name;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct dp_sudo_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create tevent request!\n");
        return NULL;
    }

    state->data = talloc_zero(state, struct dp_sudo_data);
    if (state->data == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = dp_sudo_parse_message(state, read_iter, &dp_flags,
                                &state->data->type, &state->data->rules);
    if (ret != EOK) {
        goto done;
    }

    name = dp_sudo_get_name(state->data->type);

    subreq = dp_req_send(state, provider, NULL, name, 0, sbus_req->sender->name,
                         DPT_SUDO, DPM_SUDO_HANDLER, dp_flags, state->data,
                         &state->request_name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to create subrequest!\n");
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(subreq, dp_sudo_handler_done, req);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void dp_sudo_handler_done(struct tevent_req *subreq)
{
    struct dp_sudo_handler_state *state;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct dp_sudo_handler_state);

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
dp_sudo_handler_recv(TALLOC_CTX *mem_ctx,
                     struct tevent_req *req,
                     uint16_t *_dp_error,
                     uint32_t *_error,
                     const char **_err_msg)
{
    struct dp_sudo_handler_state *state;
    state = tevent_req_data(req, struct dp_sudo_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    dp_req_reply_std(state->request_name, &state->reply,
                     _dp_error, _error, _err_msg);

    return EOK;
}
