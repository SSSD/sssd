/*
    SSSD

    ad_dyndns.c

    Authors:
        Jakub Hrozek <jhrozek@redhat.com>

    Copyright (C) 2013 Red Hat

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
#include "providers/data_provider.h"
#include "providers/dp_dyndns.h"
#include "providers/ad/ad_common.h"

void ad_dyndns_update(void *pvt);

errno_t ad_dyndns_init(struct be_ctx *be_ctx,
                       struct ad_options *ad_opts)
{
    errno_t ret;

    /* nsupdate is available. Dynamic updates
     * are supported
     */
    ret = ad_get_dyndns_options(be_ctx, ad_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set AD options\n");
        return ret;
    }

    if (dp_opt_get_bool(ad_opts->dyndns_ctx->opts,
                        DP_OPT_DYNDNS_UPDATE) == false) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Dynamic DNS updates not set\n");
        return EOK;
    }

    DEBUG(SSSDBG_CONF_SETTINGS,
          "Dynamic DNS updates are on. Checking for nsupdate..\n");
    ret = be_nsupdate_check();
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "DNS updates requested but nsupdate not available\n");
        return EOK;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not check for nsupdate\n");
        return ret;
    }

    ad_opts->be_res = be_ctx->be_res;
    if (ad_opts->be_res == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Resolver must be initialized in order "
              "to use the AD dynamic DNS updates\n");
        return EINVAL;
    }

    ret = be_nsupdate_init_timer(ad_opts->dyndns_ctx, be_ctx->ev,
                                 ad_dyndns_timer, ad_opts);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up periodic update\n");
        return ret;
    }

    ret = be_add_online_cb(be_ctx, be_ctx,
                           ad_dyndns_update,
                           ad_opts, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not set up online callback\n");
        return ret;
    }

    return EOK;
}

static void ad_dyndns_timer_connected(struct tevent_req *req);

void ad_dyndns_timer(void *pvt)
{
    struct ad_options *ctx = talloc_get_type(pvt, struct ad_options);
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
    tevent_req_set_callback(req, ad_dyndns_timer_connected, ctx);
}

static void ad_dyndns_timer_connected(struct tevent_req *req)
{
    errno_t ret;
    struct ad_options *ctx = tevent_req_callback_data(req, struct ad_options);

    ret = sdap_dyndns_timer_conn_recv(req);
    talloc_zfree(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to connect to AD: [%d](%s)\n", ret, sss_strerror(ret));
        return;
    }

    return ad_dyndns_update(ctx);
}

static struct tevent_req *ad_dyndns_update_send(struct ad_options *ctx);
static errno_t ad_dyndns_update_recv(struct tevent_req *req);
static void ad_dyndns_nsupdate_done(struct tevent_req *req);

void ad_dyndns_update(void *pvt)
{
    struct ad_options *ctx = talloc_get_type(pvt, struct ad_options);
    struct sdap_id_ctx *sdap_ctx = ctx->id_ctx->sdap_id_ctx;
    struct tevent_req *req;

    /* Schedule timer after provider went offline */
    be_nsupdate_timer_schedule(sdap_ctx->be->ev, ctx->dyndns_ctx);

    req = ad_dyndns_update_send(ctx);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Could not update DNS\n");
        return;
    }
    tevent_req_set_callback(req, ad_dyndns_nsupdate_done, NULL);
}

static void ad_dyndns_nsupdate_done(struct tevent_req *req)
{
    int ret = ad_dyndns_update_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Updating DNS entry failed [%d]: %s\n",
              ret, sss_strerror(ret));
        return;
    }

    DEBUG(SSSDBG_OP_FAILURE, "DNS update finished\n");
}

struct ad_dyndns_update_state {
    struct ad_options *ad_ctx;
    const char *servername;
};

static void ad_dyndns_sdap_update_done(struct tevent_req *subreq);

static struct tevent_req *
ad_dyndns_update_send(struct ad_options *ctx)
{
    int ret;
    struct ad_dyndns_update_state *state;
    struct tevent_req *req, *subreq;
    struct sdap_id_ctx *sdap_ctx = ctx->id_ctx->sdap_id_ctx;
    LDAPURLDesc *lud;

    DEBUG(SSSDBG_TRACE_FUNC, "Performing update\n");

    req = tevent_req_create(ctx, &state, struct ad_dyndns_update_state);
    if (req == NULL) {
        return NULL;
    }
    state->ad_ctx = ctx;

    if (ctx->dyndns_ctx->last_refresh + 60 > time(NULL) ||
        ctx->dyndns_ctx->timer_in_progress) {
        DEBUG(SSSDBG_FUNC_DATA, "Last periodic update ran recently or timer "
              "in progress, not scheduling another update\n");
        tevent_req_done(req);
        tevent_req_post(req, sdap_ctx->be->ev);
        return req;
    }
    state->ad_ctx->dyndns_ctx->last_refresh = time(NULL);

    ret = ldap_url_parse(ctx->service->sdap->uri, &lud);
    if (ret != LDAP_SUCCESS) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to parse ldap URI (%s)!\n", ctx->service->sdap->uri);
        ret = EINVAL;
        goto done;
    }

    if (lud->lud_scheme != NULL &&
        strcasecmp(lud->lud_scheme, "ldapi") == 0) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The LDAP scheme is ldapi://, cannot proceed with update\n");
        ldap_free_urldesc(lud);
        ret = EINVAL;
        goto done;
    }

    if (lud->lud_host == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "The LDAP URI (%s) did not contain a host name\n",
              ctx->service->sdap->uri);
        ldap_free_urldesc(lud);
        ret = EINVAL;
        goto done;
    }

    state->servername = talloc_strdup(state, lud->lud_host);
    ldap_free_urldesc(lud);
    if (!state->servername) {
        ret = ENOMEM;
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
                                                       AD_HOSTNAME),
                                     NULL,
                                     dp_opt_get_string(ctx->basic,
                                                       AD_KRB5_REALM),
                                     state->servername,
                                     dp_opt_get_int(ctx->dyndns_ctx->opts,
                                                    DP_OPT_DYNDNS_TTL),
                                     false);
    if (!subreq) {
        ret = EIO;
        DEBUG(SSSDBG_OP_FAILURE,
              "sdap_id_op_connect_send failed: [%d](%s)\n",
               ret, sss_strerror(ret));
        goto done;
    }
    tevent_req_set_callback(subreq, ad_dyndns_sdap_update_done, req);

    ret = EOK;
done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        tevent_req_post(req, sdap_ctx->be->ev);
    }
    return req;
}

static void ad_dyndns_sdap_update_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    errno_t ret;

    ret = sdap_dyndns_update_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Dynamic DNS update failed [%d]: %s\n",
              ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

static errno_t ad_dyndns_update_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
