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
#include <string.h>
#include <tevent.h>

#include "providers/backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"
#include "db/sysdb_sudo.h"

struct sdap_sudo_handler_state {
    uint32_t type;
    struct dp_reply_std reply;
    struct sdap_sudo_ctx *sudo_ctx;
};

static void sdap_sudo_handler_done(struct tevent_req *subreq);

static struct tevent_req *
sdap_sudo_handler_send(TALLOC_CTX *mem_ctx,
                       struct sdap_sudo_ctx *sudo_ctx,
                       struct dp_sudo_data *data,
                       struct dp_req_params *params)
{
    struct sdap_sudo_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct sdap_sudo_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->type = data->type;
    state->sudo_ctx = sudo_ctx;

    switch (data->type) {
    case BE_REQ_SUDO_FULL:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");
        subreq = sdap_sudo_full_refresh_send(state, sudo_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a refresh of specific sudo rules\n");
        subreq = sdap_sudo_rules_refresh_send(state, sudo_ctx, data->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n", data->type);
        ret = EINVAL;
        goto immediately;
    }

    if (subreq == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request: %d\n", data->type);
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, sdap_sudo_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void sdap_sudo_handler_done(struct tevent_req *subreq)
{
    struct sdap_sudo_handler_state *state;
    struct tevent_req *req;
    int dp_error;
    bool deleted;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct sdap_sudo_handler_state);

    switch (state->type) {
    case BE_REQ_SUDO_FULL:
        ret = sdap_sudo_full_refresh_recv(subreq, &dp_error);
        talloc_zfree(subreq);

        /* Reschedule the periodic task since the refresh was just finished
         * per user request. */
        if (ret == EOK && dp_error == DP_ERR_OK) {
            be_ptask_postpone(state->sudo_ctx->full_refresh);
        }
        break;
    case BE_REQ_SUDO_RULES:
        ret = sdap_sudo_rules_refresh_recv(subreq, &dp_error, &deleted);
        talloc_zfree(subreq);
        if (ret == EOK && deleted == true) {
            ret = ENOENT;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n", state->type);
        dp_error = DP_ERR_FATAL;
        ret = ERR_INTERNAL;
        break;
    }

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, NULL);
    tevent_req_done(req);
}

static errno_t
sdap_sudo_handler_recv(TALLOC_CTX *mem_ctx,
                       struct tevent_req *req,
                       struct dp_reply_std *data)
{
    struct sdap_sudo_handler_state *state = NULL;

    state = tevent_req_data(req, struct sdap_sudo_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}

static void sdap_sudo_online_cb(void *pvt)
{
    struct sdap_sudo_ctx *sudo_ctx;

    sudo_ctx = talloc_get_type(pvt, struct sdap_sudo_ctx);
    if (sudo_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "BUG: sudo_ctx is NULL\n");
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "We are back online. SUDO host information will "
                             "be renewed on next refresh.\n");
    sudo_ctx->run_hostinfo = true;
}

errno_t sdap_sudo_init(TALLOC_CTX *mem_ctx,
                       struct be_ctx *be_ctx,
                       struct sdap_id_ctx *id_ctx,
                       struct sdap_attr_map *native_map,
                       struct dp_method *dp_methods)
{
    struct sdap_sudo_ctx *sudo_ctx;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing sudo LDAP back end\n");

    sudo_ctx = talloc_zero(mem_ctx, struct sdap_sudo_ctx);
    if (sudo_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc() failed\n");
        return ENOMEM;
    }

    sudo_ctx->id_ctx = id_ctx;

    ret = ldap_get_sudo_options(be_ctx->cdb,
                                sysdb_ctx_get_ldb(be_ctx->domain->sysdb),
                                be_ctx->conf_path, id_ctx->opts, native_map,
                                &sudo_ctx->use_host_filter,
                                &sudo_ctx->include_regexp,
                                &sudo_ctx->include_netgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get SUDO options [%d]: %s\n",
              ret, sss_strerror(ret));
        goto done;
    }

    if (sudo_ctx->use_host_filter) {
        ret = be_add_online_cb(sudo_ctx, be_ctx, sdap_sudo_online_cb,
                               sudo_ctx, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to install online callback "
                  "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        /* Obtain hostinfo with the first refresh. */
        sudo_ctx->run_hostinfo = true;
    }

    ret = sdap_sudo_ptask_setup(be_ctx, sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Unable to setup periodical refresh of "
              "sudo rules [%d]: %s\n", ret, sss_strerror(ret));
        /* periodical updates will not work, but specific-rule update
         * is no affected by this, therefore we don't have to fail here */
    }

    dp_set_method(dp_methods, DPM_SUDO_HANDLER,
                  sdap_sudo_handler_send, sdap_sudo_handler_recv, sudo_ctx,
                  struct sdap_sudo_ctx, struct dp_sudo_data, struct dp_reply_std);

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sudo_ctx);
    }

    return ret;
}
