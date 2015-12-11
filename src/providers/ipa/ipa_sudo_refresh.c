/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

    Copyright (C) 2015 Red Hat

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
#include <talloc.h>
#include <tevent.h>

#include "util/util.h"
#include "providers/dp_ptask.h"
#include "providers/ipa/ipa_sudo.h"
#include "providers/ldap/sdap_sudo_shared.h"
#include "db/sysdb_sudo.h"

struct ipa_sudo_full_refresh_state {
    struct ipa_sudo_ctx *sudo_ctx;
    struct sss_domain_info *domain;
    int dp_error;
};

static void ipa_sudo_full_refresh_done(struct tevent_req *subreq);

struct tevent_req *
ipa_sudo_full_refresh_send(TALLOC_CTX *mem_ctx,
                           struct tevent_context *ev,
                           struct ipa_sudo_ctx *sudo_ctx)
{
    struct ipa_sudo_full_refresh_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    char *delete_filter;
    int ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_sudo_full_refresh_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    sudo_ctx->full_refresh_in_progress = true;

    state->domain = sudo_ctx->id_ctx->be->domain;
    state->sudo_ctx = sudo_ctx;

    /* Remove all rules from cache */
    delete_filter = talloc_asprintf(state, "(%s=%s)", SYSDB_OBJECTCLASS,
                                    SYSDB_SUDO_CACHE_OC);
    if (delete_filter == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Issuing a full refresh of sudo rules\n");

    subreq = ipa_sudo_refresh_send(state, ev, sudo_ctx, NULL, delete_filter);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ipa_sudo_full_refresh_done, req);

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

static void
ipa_sudo_full_refresh_done(struct tevent_req *subreq)
{
    struct ipa_sudo_full_refresh_state *state;
    struct tevent_req *req;
    int ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    ret = ipa_sudo_refresh_recv(subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK || state->dp_error != DP_ERR_OK) {
        goto done;
    }

    state->sudo_ctx->full_refresh_done = true;

    ret = sysdb_sudo_set_last_full_refresh(state->domain, time(NULL));
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Unable to save time of "
                                    "a successful full refresh\n");
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Successful full refresh of sudo rules\n");

done:
    state->sudo_ctx->full_refresh_in_progress = false;

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int
ipa_sudo_full_refresh_recv(struct tevent_req *req,
                           int *dp_error)
{
    struct ipa_sudo_full_refresh_state *state;
    state = tevent_req_data(req, struct ipa_sudo_full_refresh_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *dp_error = state->dp_error;

    return EOK;
}

static struct tevent_req *
ipa_sudo_ptask_full_refresh_send(TALLOC_CTX *mem_ctx,
                                 struct tevent_context *ev,
                                 struct be_ctx *be_ctx,
                                 struct be_ptask *be_ptask,
                                 void *pvt)
{
    struct ipa_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct ipa_sudo_ctx);

    return ipa_sudo_full_refresh_send(mem_ctx, be_ctx->ev, sudo_ctx);
}

static errno_t
ipa_sudo_ptask_full_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return ipa_sudo_full_refresh_recv(req, &dp_error);
}

static struct tevent_req *
ipa_sudo_ptask_smart_refresh_send(TALLOC_CTX *mem_ctx,
                                  struct tevent_context *ev,
                                  struct be_ctx *be_ctx,
                                  struct be_ptask *be_ptask,
                                  void *pvt)
{
    struct ipa_sudo_ctx *sudo_ctx;
    sudo_ctx = talloc_get_type(pvt, struct ipa_sudo_ctx);

    return ipa_sudo_full_refresh_send(mem_ctx, be_ctx->ev, sudo_ctx);
}

static errno_t
ipa_sudo_ptask_smart_refresh_recv(struct tevent_req *req)
{
    int dp_error;

    return ipa_sudo_full_refresh_recv(req, &dp_error);
}

errno_t
ipa_sudo_ptask_setup(struct be_ctx *be_ctx, struct ipa_sudo_ctx *sudo_ctx)
{
    return sdap_sudo_ptask_setup_generic(be_ctx, sudo_ctx->id_ctx->opts->basic,
                                         ipa_sudo_ptask_full_refresh_send,
                                         ipa_sudo_ptask_full_refresh_recv,
                                         ipa_sudo_ptask_smart_refresh_send,
                                         ipa_sudo_ptask_smart_refresh_recv,
                                         sudo_ctx);
}
