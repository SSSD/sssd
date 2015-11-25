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

#include "providers/dp_backend.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_sudo.h"
#include "providers/ldap/sdap_sudo_cache.h"
#include "db/sysdb_sudo.h"

static void sdap_sudo_handler(struct be_req *breq);

struct bet_ops sdap_sudo_ops = {
    .handler = sdap_sudo_handler,
    .finalize = NULL
};

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

int sdap_sudo_init(struct be_ctx *be_ctx,
                   struct sdap_id_ctx *id_ctx,
                   struct bet_ops **ops,
                   void **pvt_data)
{
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    int ret;

    DEBUG(SSSDBG_TRACE_INTERNAL, "Initializing sudo LDAP back end\n");

    sudo_ctx = talloc_zero(be_ctx, struct sdap_sudo_ctx);
    if (sudo_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc() failed\n");
        return ENOMEM;
    }

    sudo_ctx->id_ctx = id_ctx;
    *ops = &sdap_sudo_ops;
    *pvt_data = sudo_ctx;

    /* we didn't do any full refresh now,
     * so we don't have current usn values available */
    sudo_ctx->full_refresh_done = false;

    ret = ldap_get_sudo_options(id_ctx, be_ctx->cdb,
                                be_ctx->conf_path, id_ctx->opts,
                                &sudo_ctx->use_host_filter,
                                &sudo_ctx->include_regexp,
                                &sudo_ctx->include_netgroups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot get SUDO options [%d]: %s\n",
                                  ret, strerror(ret));
        goto done;
    }

    if (sudo_ctx->use_host_filter) {
        ret = be_add_online_cb(sudo_ctx, sudo_ctx->id_ctx->be,
                               sdap_sudo_online_cb, sudo_ctx, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Unable to install online callback "
                                     "[%d]: %s\n", ret, sss_strerror(ret));
            goto done;
        }

        /* Obtain hostinfo with the first refresh. */
        sudo_ctx->run_hostinfo = true;
    }

    ret = sdap_sudo_ptask_setup(sudo_ctx->id_ctx->be, sudo_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to setup periodical refresh of sudo rules [%d]: %s\n",
              ret, strerror(ret));
        /* periodical updates will not work, but specific-rule update
         * is no affected by this, therefore we don't have to fail here */
    }

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(sudo_ctx);
    }

    return ret;
}

static void sdap_sudo_reply(struct tevent_req *req)
{
    struct be_req *be_req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    int dp_error;
    bool deleted;
    int ret;

    be_req = tevent_req_callback_data(req, struct be_req);
    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        ret = sdap_sudo_full_refresh_recv(req, &dp_error);
        break;
    case BE_REQ_SUDO_RULES:
        ret = sdap_sudo_rules_refresh_recv(req, &dp_error, &deleted);
        if (ret == EOK && deleted == true) {
            ret = ENOENT;
        }
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",
                                    sudo_req->type);
        dp_error = DP_ERR_FATAL;
        ret = ERR_INTERNAL;
        break;
    }

    talloc_zfree(req);
    sdap_handler_done(be_req, dp_error, ret, strerror(ret));
}

static void sdap_sudo_handler(struct be_req *be_req)
{
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct tevent_req *req = NULL;
    struct be_sudo_req *sudo_req = NULL;
    struct sdap_sudo_ctx *sudo_ctx = NULL;
    int ret = EOK;

    if (be_is_offline(be_ctx)) {
        sdap_handler_done(be_req, DP_ERR_OFFLINE, EAGAIN, "Offline");
        return;
    }

    sudo_ctx = talloc_get_type(be_ctx->bet_info[BET_SUDO].pvt_bet_data,
                               struct sdap_sudo_ctx);

    sudo_req = talloc_get_type(be_req_get_data(be_req), struct be_sudo_req);

    switch (sudo_req->type) {
    case BE_REQ_SUDO_FULL:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");
        req = sdap_sudo_full_refresh_send(be_req, sudo_ctx);
        break;
    case BE_REQ_SUDO_RULES:
        DEBUG(SSSDBG_TRACE_FUNC, "Issuing a refresh of specific sudo rules\n");
        req = sdap_sudo_rules_refresh_send(be_req, sudo_ctx, sudo_req->rules);
        break;
    default:
        DEBUG(SSSDBG_CRIT_FAILURE, "Invalid request type: %d\n",
                                    sudo_req->type);
        ret = EINVAL;
        goto fail;
    }

    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to send request: %d\n",
                                    sudo_req->type);
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(req, sdap_sudo_reply, be_req);

    return;

fail:
    sdap_handler_done(be_req, DP_ERR_FATAL, ret, NULL);
}
