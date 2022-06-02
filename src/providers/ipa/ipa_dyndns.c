/*
    SSSD

    ipa_dyndns.c

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

    Copyright (C) 2010 Red Hat

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

#include <ctype.h>
#include "util/util.h"
#include "providers/ldap/sdap_dyndns.h"
#include "providers/ipa/ipa_common.h"
#include "providers/ipa/ipa_dyndns.h"
#include "providers/data_provider.h"
#include "providers/be_dyndns.h"

struct ipa_dyndns_update_state {
    struct ipa_options *ipa_ctx;
    struct sdap_id_op *sdap_op;
};

static void
ipa_dyndns_sdap_update_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_update_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct be_ctx *be_ctx,
                      struct be_ptask *be_ptask,
                      void *pvt);

static errno_t
ipa_dyndns_update_recv(struct tevent_req *req);

static void
ipa_dyndns_update_connect_done(struct tevent_req *subreq);


errno_t ipa_dyndns_init(struct be_ctx *be_ctx,
                        struct ipa_options *ctx)
{
    errno_t ret;
    const time_t ptask_first_delay = 10;
    int period;
    int offset;
    uint32_t extraflags = 0;

    ctx->be_res = be_ctx->be_res;
    if (ctx->be_res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Resolver must be initialized in order "
              "to use the IPA dynamic DNS updates\n");
        return EINVAL;
    }

    period = dp_opt_get_int(ctx->dyndns_ctx->opts, DP_OPT_DYNDNS_REFRESH_INTERVAL);
    if (period == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "DNS will not be updated periodically, "
              "dyndns_refresh_interval is 0\n");
        extraflags |= BE_PTASK_NO_PERIODIC;
        offset = 0;
    } else {
        offset = dp_opt_get_int(ctx->dyndns_ctx->opts, DP_OPT_DYNDNS_REFRESH_OFFSET);
    }

    ret = be_ptask_create(ctx, be_ctx, period, ptask_first_delay, 0, offset,
                          period, 0,
                          ipa_dyndns_update_send, ipa_dyndns_update_recv, ctx,
                          "Dyndns update",
                          extraflags |
                          BE_PTASK_OFFLINE_DISABLE |
                          BE_PTASK_SCHEDULE_FROM_LAST,
                          NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to setup ptask "
              "[%d]: %s\n", ret, sss_strerror(ret));
    }
    return ret;
}

static struct tevent_req *
ipa_dyndns_update_send(TALLOC_CTX *mem_ctx,
                      struct tevent_context *ev,
                      struct be_ctx *be_ctx,
                      struct be_ptask *be_ptask,
                      void *pvt)
{
    int ret;
    struct ipa_options *ctx;
    struct ipa_dyndns_update_state *state;
    struct tevent_req *req, *subreq;
    struct sdap_id_ctx *sdap_ctx;

    DEBUG(SSSDBG_TRACE_FUNC, "Performing update\n");

    ctx = talloc_get_type(pvt, struct ipa_options);
    sdap_ctx = ctx->id_ctx->sdap_id_ctx;

    req = tevent_req_create(ctx, &state, struct ipa_dyndns_update_state);
    if (req == NULL) {
        return NULL;
    }
    state->ipa_ctx = ctx;

    if (ctx->dyndns_ctx->last_refresh + 60 > time(NULL) ||
        ctx->dyndns_ctx->timer_in_progress) {
        DEBUG(SSSDBG_FUNC_DATA, "Last periodic update ran recently or timer "
              "in progress, not scheduling another update\n");
        tevent_req_done(req);
        tevent_req_post(req, sdap_ctx->be->ev);
        return req;
    }
    state->ipa_ctx->dyndns_ctx->last_refresh = time(NULL);

    /* Make sure to have a valid LDAP connection */
    state->sdap_op = sdap_id_op_create(state, sdap_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (!subreq) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: [%d](%s)\n",
              ret, sss_strerror(ret));
        ret = ENOMEM;
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_dyndns_update_connect_done, req);
    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, sdap_ctx->be->ev);
    }
    return req;
}

static void
ipa_dyndns_update_connect_done(struct tevent_req *subreq)
{
    int dp_error;
    int ret;
    struct ipa_options *ctx;
    struct tevent_req *req;
    struct ipa_dyndns_update_state *state;
    struct sdap_id_ctx *sdap_ctx;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_dyndns_update_state);

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE, "No server is available, "
                  "dynamic DNS update is skipped in offline mode.\n");
            tevent_req_error(req, ERR_DYNDNS_OFFLINE);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to LDAP server: [%d](%s)\n",
                  ret, sss_strerror(ret));
            tevent_req_error(req, ERR_NETWORK_IO);
        }
        return;
    }

    ctx = state->ipa_ctx;
    sdap_ctx = ctx->id_ctx->sdap_id_ctx;

    /* The following three checks are here to prevent SEGFAULT
     * from ticket #3076. */
    if (ctx->service == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "service structure not initialized\n");
        ret = EINVAL;
        goto done;
    }

    if (ctx->service->sdap == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "sdap structure not initialized\n");
        ret = EINVAL;
        goto done;
    }

    if (ctx->service->sdap->uri == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "LDAP uri not set\n");
        ret = EINVAL;
        goto done;
    }

    if (strncmp(ctx->service->sdap->uri,
                "ldap://", 7) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected format of LDAP URI.\n");
        ret = EIO;
        goto done;
    }

    subreq = sdap_dyndns_update_send(state, sdap_ctx->be->ev,
                                     sdap_ctx->be,
                                     ctx->dyndns_ctx->opts,
                                     sdap_ctx,
                                     ctx->dyndns_ctx->auth_type,
                                     ctx->dyndns_ctx->auth_ptr_type,
                                     dp_opt_get_string(ctx->dyndns_ctx->opts,
                                                       DP_OPT_DYNDNS_IFACE),
                                     dp_opt_get_string(ctx->basic,
                                                       IPA_HOSTNAME),
                                     dp_opt_get_string(ctx->basic,
                                                       IPA_KRB5_REALM),
                                     dp_opt_get_int(ctx->dyndns_ctx->opts,
                                                    DP_OPT_DYNDNS_TTL),
                                     true);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }
    tevent_req_set_callback(subreq, ipa_dyndns_sdap_update_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, sdap_ctx->be->ev);
    }
}

static void ipa_dyndns_sdap_update_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq, struct tevent_req);
    errno_t ret;

    ret = sdap_dyndns_update_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Dynamic DNS update failed [%d]: %s\n", ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ipa_dyndns_update_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
