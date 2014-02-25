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
#include "providers/dp_dyndns.h"

void ipa_dyndns_update(void *pvt);

errno_t ipa_dyndns_init(struct be_ctx *be_ctx,
                        struct ipa_options *ctx)
{
    errno_t ret;

    ctx->be_res = be_ctx->be_res;
    if (ctx->be_res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Resolver must be initialized in order "
              "to use the IPA dynamic DNS updates\n");
        return EINVAL;
    }

    ret = be_nsupdate_init_timer(ctx->dyndns_ctx, be_ctx->ev,
                                 ipa_dyndns_timer, ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up periodic update\n");
        return ret;
    }

    ret = be_add_online_cb(be_ctx, be_ctx,
                           ipa_dyndns_update,
                           ctx, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up online callback\n");
        return ret;
    }

    return EOK;
}

struct ipa_dyndns_timer_ctx {
    struct sdap_id_op *sdap_op;
    struct tevent_context *ev;

    struct ipa_options *ctx;
};

static void ipa_dyndns_timer_connected(struct tevent_req *req);

void ipa_dyndns_timer(void *pvt)
{
    struct ipa_options *ctx = talloc_get_type(pvt, struct ipa_options);
    struct sdap_id_ctx *sdap_ctx = ctx->id_ctx->sdap_id_ctx;
    struct tevent_req *req;

    req = sdap_dyndns_timer_conn_send(ctx, sdap_ctx->be->ev, sdap_ctx,
                                      ctx->dyndns_ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Out of memory\n");
        /* Not much we can do. Just attempt to reschedule */
        be_nsupdate_timer_schedule(sdap_ctx->be->ev, ctx->dyndns_ctx);
        return;
    }
    tevent_req_set_callback(req, ipa_dyndns_timer_connected, ctx);
}

static void ipa_dyndns_timer_connected(struct tevent_req *req)
{
    errno_t ret;
    struct ipa_options *ctx = tevent_req_callback_data(req,
                                                struct ipa_options);

    ret = sdap_dyndns_timer_conn_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to connect to IPA: [%d](%s)\n",
              ret, sss_strerror(ret));
        return;
    }

    return ipa_dyndns_update(ctx);
}

static struct tevent_req *ipa_dyndns_update_send(struct ipa_options *ctx);
static errno_t ipa_dyndns_update_recv(struct tevent_req *req);

static void ipa_dyndns_nsupdate_done(struct tevent_req *subreq);

void ipa_dyndns_update(void *pvt)
{
    struct ipa_options *ctx = talloc_get_type(pvt, struct ipa_options);
    struct sdap_id_ctx *sdap_ctx = ctx->id_ctx->sdap_id_ctx;

    /* Schedule timer after provider went offline */
    be_nsupdate_timer_schedule(sdap_ctx->be->ev, ctx->dyndns_ctx);

    struct tevent_req *req = ipa_dyndns_update_send(ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not update DNS\n");
        return;
    }
    tevent_req_set_callback(req, ipa_dyndns_nsupdate_done, NULL);
}

static void ipa_dyndns_nsupdate_done(struct tevent_req *req)
{
    int ret = ipa_dyndns_update_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Updating DNS entry failed [%d]: %s\n",
              ret, sss_strerror(ret));
        return;
    }

    DEBUG(SSSDBG_OP_FAILURE, "DNS update finished\n");
}

struct ipa_dyndns_update_state {
    struct ipa_options *ipa_ctx;
};

static void ipa_dyndns_sdap_update_done(struct tevent_req *subreq);

static struct tevent_req *
ipa_dyndns_update_send(struct ipa_options *ctx)
{
    int ret;
    struct ipa_dyndns_update_state *state;
    struct tevent_req *req, *subreq;
    struct sdap_id_ctx *sdap_ctx = ctx->id_ctx->sdap_id_ctx;
    char *dns_zone;
    const char *servername;
    int i;

    DEBUG(SSSDBG_TRACE_FUNC, "Performing update\n");

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

    dns_zone = dp_opt_get_string(ctx->basic, IPA_DOMAIN);
    if (!dns_zone) {
        ret = EIO;
        goto done;
    }

    /* The DNS zone for IPA is the lower-case
     * version of the IPA domain
     */
    for (i = 0; dns_zone[i] != '\0'; i++) {
        dns_zone[i] = tolower(dns_zone[i]);
    }

    if (strncmp(ctx->service->sdap->uri,
                "ldap://", 7) != 0) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected format of LDAP URI.\n");
        ret = EIO;
        goto done;
    }
    servername = ctx->service->sdap->uri + 7;
    if (servername[0] == '\0') {
        ret = EIO;
        goto done;
    }

    subreq = sdap_dyndns_update_send(state, sdap_ctx->be->ev,
                                     sdap_ctx->be,
                                     ctx->dyndns_ctx->opts,
                                     sdap_ctx,
                                     ctx->dyndns_ctx->auth_type,
                                     dp_opt_get_string(ctx->dyndns_ctx->opts,
                                                       DP_OPT_DYNDNS_IFACE),
                                     dp_opt_get_string(ctx->basic,
                                                       IPA_HOSTNAME),
                                     dns_zone,
                                     dp_opt_get_string(ctx->basic,
                                                       IPA_KRB5_REALM),
                                     servername,
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
    return req;
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
