/*
    SSSD

    IPA Identity Backend Module for views and overrides

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2014 Red Hat

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

#include "util/util.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_id.h"

struct ipa_get_ad_override_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_id_ctx;
    struct ipa_options *ipa_options;
    const char *ipa_realm;
    const char *ipa_view_name;
    const char *obj_sid;

    struct sdap_id_op *sdap_op;
    int dp_error;
    struct sysdb_attrs *override_attrs;
};

static void ipa_get_ad_override_connect_done(struct tevent_req *subreq);
static void ipa_get_ad_override_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_ad_override_send(TALLOC_CTX *mem_ctx,
                                            struct tevent_context *ev,
                                            struct sdap_id_ctx *sdap_id_ctx,
                                            struct ipa_options *ipa_options,
                                            const char *ipa_realm,
                                            const char *view_name,
                                            const char *obj_sid)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_ad_override_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_ad_override_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->sdap_id_ctx = sdap_id_ctx;
    state->ipa_options = ipa_options;
    state->ipa_realm = ipa_realm;
    if (strcmp(view_name, SYSDB_DEFAULT_VIEW_NAME) == 0) {
        state->ipa_view_name = IPA_DEFAULT_VIEW_NAME;
    } else {
        state->ipa_view_name = view_name;
    }
    state->obj_sid = obj_sid;
    state->dp_error = -1;
    state->override_attrs = NULL;

    state->sdap_op = sdap_id_op_create(state,
                                       state->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_ad_override_connect_done, req);

    return req;

done:
    if (ret != EOK) {
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
    } else {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    }
    tevent_req_post(req, state->ev);

    return req;
}

static void ipa_get_ad_override_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_ad_override_state *state = tevent_req_data(req,
                                              struct ipa_get_ad_override_state);
    int ret;
    char *basedn;
    char *search_base;
    char *filter;
    struct ipa_options *ipa_opts = state->ipa_options;

    ret = sdap_id_op_connect_recv(subreq, &state->dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (state->dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "No IPA server is available, going offline\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to connect to IPA server: [%d](%s)\n",
                   ret, strerror(ret));
        }

        goto fail;
    }

    ret = domain_to_basedn(state, state->ipa_realm, &basedn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "domain_to_basedn failed.\n");
        goto fail;
    }

    search_base = talloc_asprintf(state, "cn=%s,%s", state->ipa_view_name,
                                       ipa_opts->views_search_bases[0]->basedn);
    if (search_base == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    filter = talloc_asprintf(state, "(&(objectClass=%s)(%s=:SID:%s))",
                       ipa_opts->override_map[IPA_OC_OVERRIDE].name,
                       ipa_opts->override_map[IPA_AT_OVERRIDE_ANCHOR_UUID].name,
                       state->obj_sid);
    if (filter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL,
          "Searching for overrides in view [%s] for object with SID [%s].\n",
          state->ipa_view_name, state->obj_sid);

    subreq = sdap_get_generic_send(state, state->ev, state->sdap_id_ctx->opts,
                                 sdap_id_op_handle(state->sdap_op), search_base,
                                 LDAP_SCOPE_SUBTREE,
                                 filter, NULL, state->ipa_options->override_map,
                                 IPA_OPTS_OVERRIDE,
                                 dp_opt_get_int(state->sdap_id_ctx->opts->basic,
                                                SDAP_ENUM_SEARCH_TIMEOUT),
                                 false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_get_ad_override_done, req);
    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}

static void ipa_get_ad_override_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_get_ad_override_state *state = tevent_req_data(req,
                                              struct ipa_get_ad_override_state);
    int ret;
    size_t reply_count;
    struct sysdb_attrs **reply;

    ret = sdap_get_generic_recv(subreq, state, &reply_count, &reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override request failed.\n");
        goto fail;
    }

    if (reply_count == 0) {
        DEBUG(SSSDBG_TRACE_ALL, "No override found for SID [%s].\n",
                                state->obj_sid);
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
        return;
    } else if (reply_count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found [%zu] overrides for SID [%s], expected only 1.\n",
              reply_count, state->obj_sid);
        ret = EINVAL;
        goto fail;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Found override for object with SID [%s].\n",
                            state->obj_sid);

    state->override_attrs = reply[0];
    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}

errno_t ipa_get_ad_override_recv(struct tevent_req *req, int *dp_error_out,
                                 TALLOC_CTX *mem_ctx,
                                 struct sysdb_attrs **override_attrs)
{
    struct ipa_get_ad_override_state *state = tevent_req_data(req,
                                              struct ipa_get_ad_override_state);

    if (dp_error_out != NULL) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (override_attrs != NULL) {
        *override_attrs = talloc_steal(mem_ctx, state->override_attrs);
    }

    return EOK;
}
