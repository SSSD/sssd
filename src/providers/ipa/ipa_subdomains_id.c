/*
    SSSD

    IPA Identity Backend Module for sub-domains

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2012 Red Hat

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

#include "util/util.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_id.h"

struct ipa_user_get_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    int entry_type;
    const char *filter;
    int filter_type;

    const char **attrs;

    int dp_error;
};

static int ipa_get_subdomain_account_info_retry(struct tevent_req *req);
static void ipa_get_subdomain_account_info_connect_done(struct tevent_req *subreq);
static void ipa_get_subdomain_account_info_done(struct tevent_req *subreq);
struct tevent_req *ipa_get_subdomain_account_info_send(TALLOC_CTX *memctx,
                                                      struct tevent_context *ev,
                                                      struct sdap_id_ctx *ctx,
                                                      struct be_acct_req *ar)
{
    struct tevent_req *req;
    struct ipa_user_get_state *state;
    int ret;

    req = tevent_req_create(memctx, &state, struct ipa_user_get_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed\n"));
        ret = ENOMEM;
        goto fail;
    }

    state->domain = new_subdomain(state, state->ctx->be->domain, ar->domain,
                                  NULL, NULL);
    if (state->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("new_subdomain failed.\n"));
        ret = ENOMEM;
        goto fail;
    }
    state->sysdb = state->domain->sysdb;

    state->entry_type = (ar->entry_type & 0xFFF);
    state->filter = ar->filter_value;
    state->filter_type = ar->filter_type;

    switch (state->entry_type) {
        case BE_REQ_USER:
            ret = build_attrs_from_map(state, ctx->opts->user_map,
                                       SDAP_OPTS_USER, NULL,
                                       &state->attrs, NULL);
            break;
        case BE_REQ_GROUP:
            ret = build_attrs_from_map(state, ctx->opts->group_map,
                                       SDAP_OPTS_GROUP, NULL,
                                       &state->attrs, NULL);
            break;
        default:
            ret = EINVAL;
            DEBUG(SSSDBG_OP_FAILURE, ("Invalid sub-domain request type.\n"));
    }
    if (ret != EOK) goto fail;

    ret = ipa_get_subdomain_account_info_retry(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int ipa_get_subdomain_account_info_retry(struct tevent_req *req)
{
    struct ipa_user_get_state *state = tevent_req_data(req,
                                                    struct ipa_user_get_state);
    struct tevent_req *subreq;
    int ret = EOK;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        return ret;
    }

    tevent_req_set_callback(subreq, ipa_get_subdomain_account_info_connect_done,
                            req);
    return EOK;
}

static void ipa_get_subdomain_account_info_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_user_get_state *state = tevent_req_data(req,
                                                     struct ipa_user_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    const char *name;
    uint32_t id;
    char *endptr;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    switch (state->filter_type) {
        case BE_FILTER_NAME:
            name = state->filter;
            id = 0;
            break;
        case BE_FILTER_IDNUM:
            name = NULL;
            id = strtouint32(state->filter, &endptr, 10);
            if (errno || *endptr || (state->filter == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, ("Invalid sub-domain filter type.\n"));
            state->dp_error = dp_error;
            tevent_req_error(req, EINVAL);
            return;
    }

    subreq = ipa_s2n_get_acct_info_send(state,
                                        state->ev,
                                        state->ctx->opts,
                                        state->domain,
                                        sdap_id_op_handle(state->op),
                                        state->attrs,
                                        state->entry_type,
                                        name, id);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_get_subdomain_account_info_done, req);

    return;
}

static void ipa_get_subdomain_account_info_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_user_get_state *state = tevent_req_data(req,
                                                     struct ipa_user_get_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_s2n_get_acct_info_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        ret = ipa_get_subdomain_account_info_retry(req);
        if (ret != EOK) {
            tevent_req_error(req, ret);
            return;
        }

        return;
    }

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    /* FIXME: do we need some special handling of ENOENT */

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
}

int ipa_user_get_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_user_get_state *state = tevent_req_data(req,
                                                    struct ipa_user_get_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

