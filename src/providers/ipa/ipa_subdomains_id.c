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
#include "util/sss_nss.h"
#include "util/strtonum.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_async_ad.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ad/ad_id.h"
#include "providers/ad/ad_pac.h"
#include "providers/ipa/ipa_subdomains.h"

static struct tevent_req *
ipa_srv_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct sysdb_attrs *override_attrs,
                     struct dp_id_data *ar);
static errno_t
ipa_srv_ad_acct_recv(struct tevent_req *req, int *dp_error_out);

struct ipa_subdomain_account_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct dp_id_data *ar;

    bool ipa_server_mode;
    bool server_retry;
    int entry_type;
    const char *filter;
    int filter_type;
    struct sysdb_attrs *override_attrs;
    struct sysdb_attrs *mapped_attrs;
    char *object_sid;

    int dp_error;
};

static void ipa_subdomain_account_connected(struct tevent_req *subreq);
static void ipa_subdomain_account_got_override(struct tevent_req *subreq);
static void ipa_subdomain_account_done(struct tevent_req *subreq);
static errno_t ipa_subdomain_account_get_original_step(struct tevent_req *req,
                                                       struct dp_id_data *ar);

struct tevent_req *ipa_subdomain_account_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct ipa_id_ctx *ipa_ctx,
                                              struct dp_id_data *ar)
{
    struct tevent_req *req;
    struct ipa_subdomain_account_state *state;
    struct tevent_req *subreq;
    int ret;

    req = tevent_req_create(memctx, &state, struct ipa_subdomain_account_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
         return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->ctx = ipa_ctx->sdap_id_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->domain = find_domain_by_name(state->ctx->be->domain,
                                        ar->domain, true);
    if (state->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    state->sysdb = state->domain->sysdb;
    state->ar = ar;
    state->ipa_server_mode = dp_opt_get_bool(state->ipa_ctx->ipa_options->basic,
                                             IPA_SERVER_MODE);
    state->override_attrs = NULL;
    state->mapped_attrs = NULL;

    /* With views we cannot got directly to the look up the AD objects but
     * have to check first if the request matches an override in the given
     * view. But there are cases where this can be skipped and the AD object
     * can be searched directly:
     * - if no view is defined, i.e. the server does not supprt views yet
     * - searches by SID: because we do not override the SID
     * - if the responder does not send the EXTRA_INPUT_MAYBE_WITH_VIEW flags,
     *   because in this case the entry was found in the cache and the
     *   original value is used for the search (e.g. during cache updates) */
    if (state->ipa_ctx->view_name == NULL
            || state->ar->filter_type == BE_FILTER_SECID
            || (!state->ipa_server_mode
                && state->ar->extra_value != NULL
                && strcmp(state->ar->extra_value,
                          EXTRA_INPUT_MAYBE_WITH_VIEW) != 0 ))  {
        ret = ipa_subdomain_account_get_original_step(req, state->ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_subdomain_account_get_original_step failed.\n");
            goto fail;
        }

        return req;
    }

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_subdomain_account_connected, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_subdomain_account_connected(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect request failed.\n");
        goto fail;
    }

    subreq = ipa_get_ad_override_send(state, state->ev, state->ctx,
                          state->ipa_ctx->ipa_options,
                          dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                            IPA_KRB5_REALM),
                          state->ipa_ctx->view_name, state->ar);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_subdomain_account_got_override, req);

    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

#define OVERRIDE_ANCHOR_SID_PREFIX ":SID:"
#define OVERRIDE_ANCHOR_SID_PREFIX_LEN (sizeof(OVERRIDE_ANCHOR_SID_PREFIX) -1 )

static void ipa_subdomain_account_got_override(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    const char *anchor = NULL;
    struct dp_id_data *ar;

    ret = ipa_get_ad_override_recv(subreq, &dp_error, state,
                                   &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        ret = sdap_id_op_done(state->op, ret, &dp_error);

        if (dp_error == DP_ERR_OK && ret != EOK) {
            /* retry */
            subreq = sdap_id_op_connect_send(state->op, state, &ret);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed.\n");
                goto fail;
            }
            tevent_req_set_callback(subreq, ipa_subdomain_account_connected,
                                    req);
            return;
        }

        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
    }

    if (state->ar->filter_type == BE_FILTER_CERT
            && is_default_view(state->ipa_ctx->view_name)) {
        /* The override data was found with a lookup by certificate. for the
         * default view the certificate will be added to
         * SYSDB_USER_MAPPED_CERT so that cache lookups will find the same
         * user. If no override data was found the mapping (if any) should be
         * removed. For other view this is not needed because the override
         * certificate is store in the cached override object in this case. */
        state->mapped_attrs = sysdb_new_attrs(state);
        if (state->mapped_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_new_attrs failed, ignored.\n");
        } else {
            ret = sysdb_attrs_add_base64_blob(state->mapped_attrs,
                                              SYSDB_USER_MAPPED_CERT,
                                              state->ar->filter_value);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_attrs_add_base64_blob failed, ignored.\n");
                talloc_free(state->mapped_attrs);
                state->mapped_attrs = NULL;
            }
        }
    }

    if (state->override_attrs != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Processing override.\n");

        ret = sysdb_attrs_get_string(state->override_attrs,
                                     SYSDB_OVERRIDE_ANCHOR_UUID,
                                     &anchor);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto fail;
        }
        if (anchor != NULL && strncmp(OVERRIDE_ANCHOR_SID_PREFIX, anchor,
                                      OVERRIDE_ANCHOR_SID_PREFIX_LEN) == 0) {

            ret = get_dp_id_data_for_sid(state,
                                        anchor + OVERRIDE_ANCHOR_SID_PREFIX_LEN,
                                        state->ar->domain,
                                        &ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
                goto fail;
            }

            if (state->mapped_attrs != NULL) {
                /* save the SID so that SYSDB_USER_MAPPED_CERT can be added
                 * later to the object */
                state->object_sid = talloc_strdup(state, ar->filter_value);
                if (state->object_sid == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "talloc_strdup failed, ignored.\n");
                    talloc_free(state->mapped_attrs);
                    state->mapped_attrs = NULL;
                }
            }

            if (state->ipa_server_mode
                    && (state->ar->entry_type & BE_REQ_TYPE_MASK)
                                                         == BE_REQ_INITGROUPS) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Switching back to BE_REQ_INITGROUPS.\n");
                ar->entry_type = BE_REQ_INITGROUPS;
                ar->filter_type = BE_FILTER_SECID;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported override anchor type [%s].\n", anchor);
            ret = EINVAL;
            goto fail;
        }
    } else {
        if (state->mapped_attrs != NULL) {
            /* remove certificate (if any) if no matching override was found */
            ret = sysdb_remove_mapped_data(state->domain, state->mapped_attrs);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_remove_mapped_data failed, "
                                         "some cached entries might contain "
                                         "invalid mapping data.\n");
            }
            talloc_free(state->mapped_attrs);
            state->mapped_attrs = NULL;
        }
        ar = state->ar;
    }

    ret = ipa_subdomain_account_get_original_step(req, ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_subdomain_account_get_original_step failed.\n");
        goto fail;
    }

    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

static errno_t ipa_subdomain_account_get_original_step(struct tevent_req *req,
                                                       struct dp_id_data *ar)
{
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);
    struct tevent_req *subreq;

    if (state->ipa_server_mode) {
        subreq = ipa_srv_ad_acct_send(state, state->ev, state->ipa_ctx,
                                      state->override_attrs, ar);
    } else {
        subreq = ipa_get_subdom_acct_send(state, state->ev, state->ipa_ctx,
                                          state->override_attrs, ar);
    }

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_*_acct_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_subdomain_account_done, req);

    return EOK;
}


static void ipa_subdomain_account_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct ldb_result *res;
    struct sss_domain_info *object_dom;

    if (state->ipa_server_mode) {
        ret = ipa_srv_ad_acct_recv(subreq, &dp_error);
    } else {
        ret = ipa_get_subdom_acct_recv(subreq, &dp_error);
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_*_acct request failed: [%d]: %s.\n",
              ret, sss_strerror(ret));
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (state->mapped_attrs != NULL) {
        object_dom = sss_get_domain_by_sid_ldap_fallback(state->domain,
                                                         state->object_sid);
        ret = sysdb_search_object_by_sid(state,
                                         object_dom != NULL ? object_dom
                                                            : state->domain,
                                         state->object_sid, NULL, &res);
        if (ret == EOK) {
            ret = sysdb_set_entry_attr(state->domain->sysdb, res->msgs[0]->dn,
                                       state->mapped_attrs, SYSDB_MOD_ADD);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "sysdb_set_entry_attr failed, ignoring.\n");
            }
        } else if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_ALL, "No cached object found, cannot add "
                                    "mapped attribute, ignoring.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_search_object_by_sid failed, cannot add mapped "
                  "attribute, ignoring.\n");
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

errno_t ipa_subdomain_account_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_get_subdom_acct {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct sysdb_attrs *override_attrs;

    int entry_type;
    const char *filter;
    int filter_type;
    const char *extra_value;
    bool use_pac;
    struct ldb_message *user_msg;

    int dp_error;
};

static void ipa_get_subdom_acct_connected(struct tevent_req *subreq);
static void ipa_get_subdom_acct_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_subdom_acct_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct ipa_id_ctx *ipa_ctx,
                                            struct sysdb_attrs *override_attrs,
                                            struct dp_id_data *ar)
{
    struct tevent_req *req;
    struct ipa_get_subdom_acct *state;
    struct tevent_req *subreq;
    int ret;

    req = tevent_req_create(memctx, &state, struct ipa_get_subdom_acct);
    if (!req) return NULL;

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->ctx = ipa_ctx->sdap_id_ctx;
    state->dp_error = DP_ERR_FATAL;
    state->override_attrs = override_attrs;
    state->use_pac = false;

    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->domain = find_domain_by_name(state->ctx->be->domain,
                                        ar->domain, true);
    if (state->domain == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "find_domain_by_name failed.\n");
        ret = ENOMEM;
        goto fail;
    }
    state->sysdb = state->domain->sysdb;

    state->entry_type = (ar->entry_type & BE_REQ_TYPE_MASK);
    state->filter = ar->filter_value;
    state->filter_type = ar->filter_type;
    state->extra_value = ar->extra_value;

    switch (state->entry_type) {
        case BE_REQ_USER:
        case BE_REQ_GROUP:
        case BE_REQ_BY_SECID:
        case BE_REQ_BY_CERT:
        case BE_REQ_USER_AND_GROUP:
            ret = EOK;
            break;
        case BE_REQ_INITGROUPS:
            ret = check_if_pac_is_available(state, state->domain, ar,
                                            &state->user_msg);
            if (ret == EOK) {
                state->use_pac = true;
            }

            ret = EOK;
            break;
        default:
            ret = EINVAL;
            if (state->entry_type > BE_REQ__LAST) {
                DEBUG(SSSDBG_OP_FAILURE, "Invalid sub-domain request type %d.\n",
                      state->entry_type);
            } else {
                DEBUG(SSSDBG_TRACE_FUNC, "Unhandled sub-domain request type %d.\n",
                      state->entry_type);
            }
    }
    if (ret != EOK) goto fail;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_get_subdom_acct_connected, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_get_subdom_acct_connected(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);
    int dp_error = DP_ERR_FATAL;
    int ret;
    char *endptr;
    struct req_input *req_input;
    char *shortname;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (state->entry_type == BE_REQ_INITGROUPS) {
        /* With V1/V2 of the extdom plugin a user lookup will resolve the full
         * group membership of the user. */
        if (sdap_is_extension_supported(sdap_id_op_handle(state->op),
                                        EXOP_SID2NAME_V1_OID) ||
            sdap_is_extension_supported(sdap_id_op_handle(state->op),
                                        EXOP_SID2NAME_V2_OID)) {
            state->entry_type = BE_REQ_USER;
        } else {
            if (state->use_pac && state->user_msg != NULL) {
                /* This means the user entry is already in the cache and has
                 * the pac attached, we only have look up the missing groups
                 * and add the user to all groups. */

                subreq = ipa_get_subdom_acct_process_pac_send(state, state->ev,
                                                   sdap_id_op_handle(state->op),
                                                   state->ipa_ctx,
                                                   state->domain,
                                                   state->user_msg);
                if (subreq == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE,
                          "ipa_get_subdom_acct_process_pac failed.\n");
                    tevent_req_error(req, ENOMEM);
                    return;
                }
                tevent_req_set_callback(subreq, ipa_get_subdom_acct_done, req);

                return;
            }

            /* Fall through if there is no PAC */

            DEBUG(SSSDBG_TRACE_FUNC, "Initgroups requests are not handled " \
                                      "by the IPA provider but are resolved " \
                                      "by the responder directly from the " \
                                      "cache.\n");
            tevent_req_error(req, ENOTSUP);
            return;
        }
    }

    req_input = talloc(state, struct req_input);
    if (req_input == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc failed.\n");
        tevent_req_error(req, ENOMEM);
        return;
    }

    switch (state->filter_type) {
        case BE_FILTER_NAME:
            req_input->type = REQ_INP_NAME;
            /* The extdom plugin expects the shortname and domain separately,
             * but for UPN/email lookup we need to send the raw name */
            if (state->extra_value != NULL
                    && strcmp(state->extra_value, EXTRA_NAME_IS_UPN) == 0) {
                req_input->inp.name = talloc_strdup(req_input, state->filter);
            } else {
                ret = sss_parse_internal_fqname(req_input, state->filter,
                                                &shortname, NULL);
                if (ret != EOK) {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Cannot parse internal name [%s]: %d\n",
                          state->filter, ret);
                    tevent_req_error(req, ret);
                    return;
                }

                req_input->inp.name = talloc_steal(req_input, shortname);
            }
            if (req_input->inp.name == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                tevent_req_error(req, ENOMEM);
                return;
            }
            break;
        case BE_FILTER_IDNUM:
            req_input->type = REQ_INP_ID;
            req_input->inp.id = strtouint32(state->filter, &endptr, 10);
            if (errno || *endptr || (state->filter == endptr)) {
                tevent_req_error(req, errno ? errno : EINVAL);
                return;
            }
            break;
        case BE_FILTER_SECID:
            req_input->type = REQ_INP_SECID;
            req_input->inp.secid = talloc_strdup(req_input, state->filter);
            if (req_input->inp.secid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                tevent_req_error(req, ENOMEM);
                return;
            }
            break;
        case BE_FILTER_CERT:
            if (sdap_is_extension_supported(sdap_id_op_handle(state->op),
                                            EXOP_SID2NAME_V1_OID) ||
                sdap_is_extension_supported(sdap_id_op_handle(state->op),
                                            EXOP_SID2NAME_V2_OID)) {
                req_input->type = REQ_INP_CERT;
                req_input->inp.cert = talloc_strdup(req_input, state->filter);
                if (req_input->inp.cert == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    tevent_req_error(req, ENOMEM);
                    return;
                }
            } else {
                DEBUG(SSSDBG_OP_FAILURE,
                      "Lookup by certificate not supported by the server.\n");
                state->dp_error = DP_ERR_OK;
                tevent_req_error(req, EINVAL);
                return;
            }
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Invalid sub-domain filter type.\n");
            state->dp_error = dp_error;
            tevent_req_error(req, EINVAL);
            return;
    }

    subreq = ipa_s2n_get_acct_info_send(state,
                                        state->ev,
                                        state->ipa_ctx,
                                        state->ctx->opts,
                                        state->domain,
                                        state->override_attrs,
                                        sdap_id_op_handle(state->op),
                                        state->entry_type,
                                        req_input);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_get_subdom_acct_done, req);

    return;
}

static void ipa_get_subdom_acct_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_s2n_get_acct_info_recv(subreq);
    talloc_zfree(subreq);

    ret = sdap_id_op_done(state->op, ret, &dp_error);
    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, ipa_get_subdom_acct_connected, req);
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

int ipa_get_subdom_acct_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_get_subdom_acct *state = tevent_req_data(req,
                                                struct ipa_get_subdom_acct);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

static struct ad_id_ctx *ipa_get_ad_id_ctx(struct ipa_id_ctx *ipa_ctx,
                                           struct sss_domain_info *dom);

static struct sdap_id_conn_ctx **
ipa_ad_gc_conn_list(TALLOC_CTX *mem_ctx, struct ipa_id_ctx *ipa_ctx,
                    struct ad_id_ctx *ad_ctx, struct sss_domain_info *dom)
{
    struct ad_id_ctx *forest_root_ad_id_ctx;
    struct sdap_id_conn_ctx **clist;
    int cindex = 0;

    /* While creating the domains and sub-domains each domain gets a global
     * catalog services assigned but only one should be used because the
     * global catalog is by definition responsible for the whole forest so it
     * does not make sense to use a global catalog service for each domain and
     * in the worst case connect to the same GC multiple times.
     *
     * In the AD provider this is simple because the GC service of the
     * configured domain AD_GC_SERVICE_NAME ("AD_GC") can be used. In the IPA
     * case all domains from the trusted forest are on the level of
     * sub-domains so we have to pick one. Since the forest root is linked
     * from all domain of the same forest it will be the most straight forward
     * choice. */
    forest_root_ad_id_ctx = ipa_get_ad_id_ctx(ipa_ctx, dom->forest_root);
    if (forest_root_ad_id_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing ad_id_ctx for forest root.\n");
        return NULL;
    }

    clist = talloc_zero_array(mem_ctx, struct sdap_id_conn_ctx *, 3);
    if (clist == NULL) return NULL;

    /* Always try GC first */
    if (dp_opt_get_bool(forest_root_ad_id_ctx->ad_options->basic,
                        AD_ENABLE_GC)) {
        clist[cindex] = forest_root_ad_id_ctx->gc_ctx;
        clist[cindex]->ignore_mark_offline = true;
        clist[cindex]->no_mpg_user_fallback = true;
        cindex++;
    }

    clist[cindex] = ad_get_dom_ldap_conn(ad_ctx, dom);

    return clist;
}

/* IPA lookup for server mode. Directly to AD. */
struct ipa_get_ad_acct_state {
    int dp_error;
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct dp_id_data *ar;
    struct sss_domain_info *obj_dom;
    char *object_sid;
    struct sysdb_attrs *override_attrs;
    struct ldb_message *obj_msg;
};

static void ipa_get_ad_acct_ad_part_done(struct tevent_req *subreq);
static void ipa_get_ad_override_done(struct tevent_req *subreq);
static errno_t ipa_get_ad_apply_override_step(struct tevent_req *req);
static errno_t ipa_get_ad_ipa_membership_step(struct tevent_req *req);
static void ipa_id_get_groups_overrides_done(struct tevent_req *subreq);
static void ipa_get_ad_acct_done(struct tevent_req *subreq);

static enum ipa_trust_type
ipa_get_trust_type(struct ipa_id_ctx *ipa_ctx,
                   struct sss_domain_info *dom);
static struct tevent_req *
ipa_get_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct sysdb_attrs *override_attrs,
                     struct dp_id_data *ar)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_ad_acct_state *state;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx **clist;
    struct sdap_id_ctx *sdap_id_ctx;
    struct ad_id_ctx *ad_id_ctx;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_ad_acct_state);
    if (req == NULL) return NULL;

    state->dp_error = -1;
    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->ar = ar;
    state->obj_msg = NULL;
    state->override_attrs = override_attrs;

    /* This can only be a subdomain request, verify subdomain */
    state->obj_dom = find_domain_by_name(ipa_ctx->sdap_id_ctx->be->domain,
                                         ar->domain, true);
    if (state->obj_dom == NULL) {
        ret = EINVAL;
        goto fail;
    }

    /* Let's see if this subdomain has a ad_id_ctx */
    ad_id_ctx = ipa_get_ad_id_ctx(ipa_ctx, state->obj_dom);
    if (ad_id_ctx == NULL) {
        ret = EINVAL;
        goto fail;
    }
    sdap_id_ctx = ad_id_ctx->sdap_id_ctx;

    /* We read users and groups from GC. From groups, we may switch to
     * using LDAP connection in the group request itself, but in order
     * to resolve Universal group memberships, we also need the GC
     * connection
     */
    switch (state->ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_INITGROUPS:
    case BE_REQ_BY_SECID:
    case BE_REQ_GROUP:
        clist = ipa_ad_gc_conn_list(req, ipa_ctx, ad_id_ctx, state->obj_dom);
        break;
    default:
        clist = ad_ldap_conn_list(req, ad_id_ctx, state->obj_dom);
        break;
    }

    if (clist == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot generate AD connection list!\n");
        ret = ENOMEM;
        goto fail;
    }

    /* Now we already need ad_id_ctx in particular sdap_id_conn_ctx */
    sdom = sdap_domain_get(sdap_id_ctx->opts, state->obj_dom);
    if (sdom == NULL) {
        ret = EIO;
        goto fail;
    }

    subreq = ad_handle_acct_info_send(req, ar, sdap_id_ctx,
                                      ad_id_ctx->ad_options, sdom, clist);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_get_ad_acct_ad_part_done, req);
    return req;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static struct ad_id_ctx *
ipa_get_ad_id_ctx(struct ipa_id_ctx *ipa_ctx,
                  struct sss_domain_info *dom)
{
    struct ipa_ad_server_ctx *iter;

    DLIST_FOR_EACH(iter, ipa_ctx->server_mode->trusts) {
        if (iter->dom == dom) break;
    }

    return (iter) ? iter->ad_id_ctx : NULL;
}

static enum ipa_trust_type
ipa_get_trust_type(struct ipa_id_ctx *ipa_ctx,
                   struct sss_domain_info *dom)
{
    struct ipa_subdom_server_ctx *iter;

    DLIST_FOR_EACH(iter, ipa_ctx->server_mode->trusts) {
        if (iter->dom == dom) break;
    }

    return iter->type;
}

static errno_t
get_subdomain_homedir_of_user(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                              const char *fqname, uint32_t uid,
                              const char *original, const char **_homedir)
{
    errno_t ret;
    const char *homedir;
    TALLOC_CTX *tmp_ctx;
    struct sss_nss_homedir_ctx homedir_ctx;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    if (strstr(dom->subdomain_homedir, "%o") != NULL && original == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "Original home directory for user: %s is empty.\n", fqname);
        ret = ERR_HOMEDIR_IS_NULL;
        goto done;
    }

    memset(&homedir_ctx, 0, sizeof(homedir_ctx));

    homedir_ctx.uid = uid;
    homedir_ctx.username = fqname;
    homedir_ctx.domain = dom->name;
    homedir_ctx.flatname = dom->flat_name;
    homedir_ctx.config_homedir_substr = dom->homedir_substr;
    homedir_ctx.original = original;

    /* To be compatible with the old winbind based user lookups and IPA
     * clients the user name in the home directory path will be lower-case. */
    homedir = expand_homedir_template(tmp_ctx, dom->subdomain_homedir,
                                      false, &homedir_ctx);
    if (homedir == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "expand_homedir_template failed\n");
        ret = ENOMEM;
        goto done;
    }

    if (_homedir == NULL) {
        ret = EINVAL;
        goto done;
    }
    *_homedir = talloc_steal(mem_ctx, homedir);

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
store_homedir_of_user(struct sss_domain_info *domain,
                      const char *fqname, const char *homedir)
{
    errno_t ret;
    errno_t sret;
    TALLOC_CTX *tmp_ctx;
    bool in_transaction = false;
    struct sysdb_attrs *attrs;
    struct sysdb_ctx *sysdb = domain->sysdb;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        goto done;
    }

    attrs = sysdb_new_attrs(tmp_ctx);
    if (attrs == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_HOMEDIR, homedir);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Error setting homedir: [%s]\n",
                                     strerror(ret));
        goto done;
    }

    ret = sysdb_transaction_start(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }

    in_transaction = true;

    ret = sysdb_set_user_attr(domain, fqname, attrs, SYSDB_MOD_REP);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Failed to update homedir information!\n");
        goto done;
    }

    ret = sysdb_transaction_commit(sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Cannot commit sysdb transaction [%d]: %s.\n",
               ret, strerror(ret));
        goto done;
    }

    in_transaction = false;

done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction.\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
apply_subdomain_homedir(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                        struct ldb_message *msg)
{
    errno_t ret;
    uint32_t uid;
    const char *fqname;
    const char *original;
    const char *homedir = NULL;
    struct ldb_message_element *msg_el = NULL;
    size_t c;
    const char *category = NULL;
    size_t length = 0;
    bool user_class = true;

    msg_el = ldb_msg_find_element(msg, SYSDB_OBJECTCATEGORY);
    if (msg_el == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_find_element failed.\n");
        ret = ENOENT;
        goto done;
    }

    /* The object is a user if SYSDB_OBJECTCATEGORY is SYSDB_USER_CLASS or in
     * case of a MPG group lookup if SYSDB_OBJECTCATEGORY is SYSDB_GROUP_CLASS.
     */
    for (c = 0; c < msg_el->num_values; c++) {
        category = (const char *)msg_el->values[c].data;
        length = msg_el->values[c].length;
        if (strncmp(SYSDB_USER_CLASS, category, length) == 0) {
            user_class = true;
            break;
        }
        if (sss_domain_is_mpg(dom)
               && strncmp(SYSDB_GROUP_CLASS, category, length) == 0) {
            user_class = false;
            break;
        }
    }
    if (c == msg_el->num_values) {
        DEBUG(SSSDBG_TRACE_ALL,
              "User objectclass not found, object is not a user.\n");
        ret = ENOENT;
        goto done;
    }

    fqname = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (fqname == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing user name.\n");
        ret = EINVAL;
        goto done;
    }

    uid = ldb_msg_find_attr_as_uint64(msg, SYSDB_UIDNUM, 0);
    if (uid == 0) {
        if (user_class) {
            DEBUG(SSSDBG_OP_FAILURE, "UID for user [%s] is unknown\n", fqname);
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "No UID for object [%s], perhaps mpg\n", fqname);
        }
        ret = ENOENT;
        goto done;
    }

    original = ldb_msg_find_attr_as_string(msg, SYSDB_HOMEDIR, NULL);
    if (original == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Missing homedir of %s.\n", fqname);
    }

    ret = get_subdomain_homedir_of_user(mem_ctx, dom, fqname, uid, original,
                                        &homedir);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "get_subdomain_homedir_of_user failed: [%d]: [%s]\n",
              ret, sss_strerror(ret));
        if (ret == ERR_HOMEDIR_IS_NULL) {
            /* This is not fatal, fallback_homedir will be used. */
            ret = EOK;
        }
        goto done;
    }

    ret = store_homedir_of_user(dom, fqname, homedir);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "store_homedir_of_user failed: [%d]: [%s]\n",
               ret, sss_strerror(ret));
        goto done;
    }

done:
    return ret;
}

errno_t get_object_from_cache(TALLOC_CTX *mem_ctx,
                              struct sss_domain_info *dom,
                              struct dp_id_data *ar,
                              struct ldb_message **_msg)
{
    errno_t ret;
    uint32_t id;
    struct ldb_message *msg = NULL;
    struct ldb_result *res = NULL;
    char *endptr;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_UIDNUM,
                            SYSDB_SID_STR,
                            SYSDB_OBJECTCATEGORY,
                            SYSDB_UUID,
                            SYSDB_GHOST,
                            SYSDB_HOMEDIR,
                            NULL };

    if (ar->filter_type == BE_FILTER_SECID) {
        ret = sysdb_search_object_by_sid(mem_ctx, dom, ar->filter_value, attrs,
                                         &res);
        if (ret == EOK) {
            *_msg = res->msgs[0];
        }
        goto done;
    } else if (ar->filter_type == BE_FILTER_UUID) {
        ret = sysdb_search_object_by_uuid(mem_ctx, dom, ar->filter_value, attrs,
                                          &res);
        if (ret == EOK) {
            *_msg = res->msgs[0];
        }
        goto done;
    } else if (ar->filter_type == BE_FILTER_CERT) {
        ret = sysdb_search_object_by_cert(mem_ctx, dom, ar->filter_value, attrs,
                                          &res);
        if (ret == EOK) {
            if (res->count != 1) {
                DEBUG(SSSDBG_OP_FAILURE,
                      "More than one result found in our cache\n");
                ret = EINVAL;
            } else {
                *_msg = res->msgs[0];
            }
        }
        goto done;
    } else if (ar->filter_type == BE_FILTER_IDNUM) {
        id = strtouint32(ar->filter_value, &endptr, 10);
        if ((errno != 0) || *endptr || (ar->filter_value == endptr)) {
            ret = errno ? errno : EINVAL;
            DEBUG(SSSDBG_OP_FAILURE, "strtouint32 failed.\n");
            goto done;
        }

        switch (ar->entry_type & BE_REQ_TYPE_MASK) {
        case BE_REQ_GROUP:
            ret = sysdb_getgrgid_attrs(mem_ctx, dom, id, attrs, &res);
            if (ret == EOK) {
                if (res->count == 0) {
                    ret = ENOENT;
                } else {
                    msg = res->msgs[0];
                }
            }
            break;
        case BE_REQ_INITGROUPS:
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:
            ret = sysdb_search_user_by_uid(mem_ctx, dom, id, attrs, &msg);
            if (ret == ENOENT && (ar->entry_type & BE_REQ_TYPE_MASK)
                                                     == BE_REQ_USER_AND_GROUP) {
                ret = sysdb_getgrgid_attrs(mem_ctx, dom, id, attrs, &res);
                if (ret == EOK) {
                    if (res->count == 0) {
                        ret = ENOENT;
                    } else {
                        msg = res->msgs[0];
                    }
                }
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected entry type [%d].\n",
                                        (ar->entry_type & BE_REQ_TYPE_MASK));
            ret = EINVAL;
            goto done;
        }
    } else if (ar->filter_type == BE_FILTER_NAME) {
        switch (ar->entry_type & BE_REQ_TYPE_MASK) {
        case BE_REQ_GROUP:
            ret = sysdb_search_group_by_name(mem_ctx, dom, ar->filter_value,
                                             attrs, &msg);
            break;
        case BE_REQ_INITGROUPS:
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:
            if (ar->extra_value
                    && strcmp(ar->extra_value, EXTRA_NAME_IS_UPN) == 0) {
                ret = sysdb_search_user_by_upn(mem_ctx, dom, false, ar->filter_value,
                                               attrs, &msg);
            } else {
                ret = sysdb_search_user_by_name(mem_ctx, dom, ar->filter_value,
                                                attrs, &msg);
                if (ret == ENOENT && (ar->entry_type & BE_REQ_TYPE_MASK)
                                                     == BE_REQ_USER_AND_GROUP) {
                    ret = sysdb_search_group_by_name(mem_ctx, dom,
                                                     ar->filter_value, attrs,
                                                     &msg);
                }
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected entry type [%d].\n",
                                        (ar->entry_type & BE_REQ_TYPE_MASK));
            ret = EINVAL;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected filter type.\n");
        ret = EINVAL;
        goto done;
    }

    if (ret == EOK) {
        *_msg = msg;
    }

done:
    if (ret != EOK) {
        if (ret != ENOENT) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make request to our cache: [%d]: [%s]\n",
                   ret, sss_strerror(ret));
        } else {
            DEBUG(SSSDBG_FUNC_DATA, "Object wasn't found in cache\n");
        }
    }

    return ret;
}

static void
ipa_get_ad_acct_ad_part_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;
    const char *sid;
    struct dp_id_data *ar;

    ret = ad_handle_acct_info_recv(subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret == ERR_SUBDOM_INACTIVE) {
        tevent_req_error(req, ret);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "AD lookup failed: %d\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    ret = get_object_from_cache(state, state->obj_dom, state->ar,
                                &state->obj_msg);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Object not found, ending request\n");
        tevent_req_done(req);
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_object_from_cache failed.\n");
        goto fail;
    }

    ret = apply_subdomain_homedir(state, state->obj_dom,
                                  state->obj_msg);
    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "apply_subdomain_homedir failed: [%d]: [%s].\n",
               ret, sss_strerror(ret));
        goto fail;
    }

    if (state->override_attrs == NULL) {
        sid = ldb_msg_find_attr_as_string(state->obj_msg, SYSDB_SID_STR, NULL);
        if (sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find a SID.\n");
            ret = EINVAL;
            goto fail;
        }

        state->object_sid = talloc_strdup(state, sid);
        if (state->object_sid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto fail;
        }

        ret = get_dp_id_data_for_sid(state, state->object_sid,
                                      state->obj_dom->name, &ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
            goto fail;
        }

        subreq = ipa_get_ad_override_send(state, state->ev,
                                          state->ipa_ctx->sdap_id_ctx,
                                          state->ipa_ctx->ipa_options,
                                          state->ipa_ctx->server_mode->realm,
                                          state->ipa_ctx->view_name,
                                          ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_override_send failed.\n");
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_get_ad_override_done, req);
    } else {
        ret = ipa_get_ad_apply_override_step(req);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_get_ad_apply_override_step failed.\n");
            goto fail;
        }
    }

    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}


static void
ipa_get_ad_override_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;

    ret = ipa_get_ad_override_recv(subreq, &state->dp_error, state,
                                   &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        tevent_req_error(req, ret);
        return;

    }

    ret = ipa_get_ad_apply_override_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_apply_override_step failed.\n");
        goto fail;
    }

    return;

fail:
    state->dp_error = DP_ERR_FATAL;
    tevent_req_error(req, ret);
    return;
}

static void ipa_check_ghost_members_done(struct tevent_req *subreq);
static errno_t ipa_check_ghost_members(struct tevent_req *req)
{
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;
    struct tevent_req *subreq;
    struct ldb_message_element *ghosts = NULL;


    if (state->obj_msg == NULL) {
        ret = get_object_from_cache(state, state->obj_dom, state->ar,
                                    &state->obj_msg);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Object not found, ending request\n");
            return EOK;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_object_from_cache failed.\n");
            return ret;
        }
    }

    ghosts = ldb_msg_find_element(state->obj_msg, SYSDB_GHOST);

    if (ghosts != NULL) {
        /* Resolve ghost members */
        subreq = ipa_resolve_user_list_send(state, state->ev,
                                            state->ipa_ctx,
                                            state->obj_dom->name,
                                            ghosts);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list_send failed.\n");
            return ENOMEM;
        }
        tevent_req_set_callback(subreq, ipa_check_ghost_members_done, req);
        return EAGAIN;
    }

    return EOK;
}

static void ipa_check_ghost_members_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    int ret;

    ret = ipa_resolve_user_list_recv(subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list request failed [%d]\n",
                                  ret);
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
    return;
}

static errno_t ipa_get_ad_apply_override_step(struct tevent_req *req)
{
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;
    struct tevent_req *subreq;
    const char *obj_name;
    int entry_type;
    size_t groups_count = 0;
    struct ldb_message **groups = NULL;
    const char *attrs[] = SYSDB_INITGR_ATTRS;

    if (state->override_attrs != NULL) {
        /* We are in ipa-server-mode, so the view is the default view by
         * definition. */
        ret = sysdb_apply_default_override(state->obj_dom,
                                           state->override_attrs,
                                           state->obj_msg->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_apply_default_override failed.\n");
            return ret;
        }
    }

    entry_type = (state->ar->entry_type & BE_REQ_TYPE_MASK);
    if (entry_type != BE_REQ_INITGROUPS
            && entry_type != BE_REQ_USER
            && entry_type != BE_REQ_BY_SECID
            && entry_type != BE_REQ_GROUP) {
        tevent_req_done(req);
        return EOK;
    }

    /* expand ghost members, if any, to get group members with overrides
     * right. */
    if (entry_type == BE_REQ_GROUP) {
        ret = ipa_check_ghost_members(req);
        if (ret == EOK) {
            tevent_req_done(req);
            return EOK;
        } else if (ret == EAGAIN) {
            return EOK;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_check_ghost_members failed.\n");
            return ret;
        }
    }

    /* Replace ID with name in search filter */
    if ((entry_type == BE_REQ_USER && state->ar->filter_type == BE_FILTER_IDNUM)
            || (entry_type == BE_REQ_INITGROUPS
                    && state->ar->filter_type == BE_FILTER_SECID)
            || entry_type == BE_REQ_BY_SECID) {
        if (state->obj_msg == NULL) {
            ret = get_object_from_cache(state, state->obj_dom, state->ar,
                                        &state->obj_msg);
            if (ret == ENOENT) {
                DEBUG(SSSDBG_MINOR_FAILURE,
                      "Object not found, ending request\n");
                tevent_req_done(req);
                return EOK;
            } else if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_object_from_cache failed.\n");
                return ret;
            }
        }

        obj_name = ldb_msg_find_attr_as_string(state->obj_msg, SYSDB_NAME,
                                               NULL);
        if (obj_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cached object has no name.\n");
            return EINVAL;
        }

        state->ar->filter_value = talloc_strdup(state->ar, obj_name);
        if (state->ar->filter_value == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
            return ENOMEM;
        }
        state->ar->filter_type = BE_FILTER_NAME;
        state->ar->entry_type = BE_REQ_USER;
    }

    /* Lookup all groups the user is a member of which do not have ORIGINALAD
     * attributes set, i.e. where overrides might not have been applied. */
    ret = sysdb_asq_search(state, state->obj_dom, state->obj_msg->dn,
                          "(&("SYSDB_GC")("SYSDB_GIDNUM"=*)" \
                            "("SYSDB_POSIX"=TRUE)" \
                            "(!("ORIGINALAD_PREFIX SYSDB_GIDNUM"=*))" \
                            "(!("ORIGINALAD_PREFIX SYSDB_NAME"=*)))",
                          SYSDB_INITGR_ATTR,
                          attrs, &groups_count, &groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_groups_without_orig failed.\n");
        return ret;
    }

    if (groups != NULL) {
        subreq = ipa_initgr_get_overrides_send(state, state->ev, state->ipa_ctx,
                                               state->obj_dom, groups_count,
                                               groups, SYSDB_SID_STR);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_initgr_get_overrides_send failed.\n");
            return ENOMEM;
        }
        tevent_req_set_callback(subreq, ipa_id_get_groups_overrides_done, req);
        return EOK;
    }

    ret = ipa_get_ad_ipa_membership_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_ipa_membership_step failed.\n");
        return ret;
    }

    return EOK;
}

static void ipa_id_get_groups_overrides_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    errno_t ret;

    ret = ipa_initgr_get_overrides_recv(subreq, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "IPA resolve user groups overrides failed [%d].\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    ret = ipa_get_ad_ipa_membership_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_ipa_membership_step failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    return;
}

static errno_t ipa_get_ad_ipa_membership_step(struct tevent_req *req)
{
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    struct tevent_req *subreq;

    /* For initgroups request we have to check IPA group memberships of AD
     * users. This has to be done for other user-request as well to make sure
     * IPA related attributes are not overwritten. */
    subreq = ipa_get_ad_memberships_send(state, state->ev, state->ar,
                                         state->ipa_ctx->server_mode,
                                         state->obj_dom,
                                         state->ipa_ctx->sdap_id_ctx,
                                         state->ipa_ctx->server_mode->realm);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ad_memberships_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_get_ad_acct_done, req);

    return EOK;
}

static void
ipa_get_ad_acct_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);
    errno_t ret;

    ret = ipa_get_ad_memberships_recv(subreq, &state->dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA external groups lookup failed: %d\n",
                                  ret);
        tevent_req_error(req, ret);
        return;

    }

    tevent_req_done(req);
}

static errno_t
ipa_get_ad_acct_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_get_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_get_ad_acct_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_srv_ad_acct_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sysdb_attrs *override_attrs;
    struct dp_id_data *ar;

    struct sss_domain_info *obj_dom;
    struct be_ctx *be_ctx;
    bool retry;

    int dp_error;
};

static int ipa_srv_ad_acct_lookup_step(struct tevent_req *req);
static void ipa_srv_ad_acct_lookup_done(struct tevent_req *subreq);
static void ipa_srv_ad_acct_retried(struct tevent_req *subreq);

static struct tevent_req *
ipa_srv_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct sysdb_attrs *override_attrs,
                     struct dp_id_data *ar)
{
    errno_t ret;
    struct tevent_req *req;
    struct ipa_srv_ad_acct_state *state;

    req = tevent_req_create(mem_ctx, &state, struct ipa_srv_ad_acct_state);
    if (req == NULL) {
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->override_attrs = override_attrs;
    state->ar = ar;
    state->retry = true;
    state->dp_error = DP_ERR_FATAL;
    state->be_ctx = ipa_ctx->sdap_id_ctx->be;

    state->obj_dom = find_domain_by_name(
                                  state->ipa_ctx->sdap_id_ctx->be->domain,
                                  state->ar->domain, true);
    if (state->obj_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Domain not found\n");
        ret = ERR_DOMAIN_NOT_FOUND;
        goto fail;
    }

    ret = ipa_srv_ad_acct_lookup_step(req);
    if (ret != EOK) {
        goto fail;
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static int ipa_srv_ad_acct_lookup_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ipa_srv_ad_acct_state *state = tevent_req_data(req,
                                            struct ipa_srv_ad_acct_state);

    DEBUG(SSSDBG_TRACE_FUNC, "Looking up AD account\n");
    subreq = ipa_get_ad_acct_send(state, state->ev, state->ipa_ctx,
                                  state->override_attrs,
                                  state->ar);
    if (subreq == NULL) {
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_srv_ad_acct_lookup_done, req);

    return EOK;
}

static void ipa_srv_ad_acct_lookup_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error = DP_ERR_FATAL;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_srv_ad_acct_state *state = tevent_req_data(req,
                                            struct ipa_srv_ad_acct_state);

    ret = ipa_get_ad_acct_recv(subreq, &dp_error);
    talloc_free(subreq);
    if (ret == ERR_SUBDOM_INACTIVE && state->retry == true) {

        state->retry = false;

        DEBUG(SSSDBG_MINOR_FAILURE,
              "Subdomain lookup failed, will try to reset subdomain.\n");
        subreq = ipa_server_trusted_dom_setup_send(state, state->ev,
                                                   state->be_ctx,
                                                   state->ipa_ctx,
                                                   state->obj_dom);
        if (subreq == NULL) {
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_srv_ad_acct_retried, req);
        return;
    } else if (ret != EOK) {
        be_mark_dom_offline(state->obj_dom, state->be_ctx);

        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_*_acct request failed: [%d]: %s.\n",
              ret, sss_strerror(ret));
        goto fail;
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
}

static void ipa_srv_ad_acct_retried(struct tevent_req *subreq)
{
    errno_t ret;
    struct ad_id_ctx *ad_id_ctx;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_srv_ad_acct_state *state = tevent_req_data(req,
                                            struct ipa_srv_ad_acct_state);

    ret = ipa_server_trusted_dom_setup_recv(subreq);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to re-set subdomain [%d]: %s\n", ret, sss_strerror(ret));
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Subdomain re-set, will retry lookup\n");
    ad_id_ctx = ipa_get_ad_id_ctx(state->ipa_ctx, state->obj_dom);
    if (ad_id_ctx == NULL || ad_id_ctx->ad_options == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No AD ID ctx or no ID CTX options?\n");
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, EINVAL);
        return;
    }

    ad_failover_reset(state->be_ctx, ad_id_ctx->ad_options->service);

    ret = ipa_srv_ad_acct_lookup_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to look up AD acct [%d]: %s\n", ret, sss_strerror(ret));
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
        return;
    }
}

static errno_t
ipa_srv_ad_acct_recv(struct tevent_req *req, int *dp_error_out)
{
    struct ipa_srv_ad_acct_state *state = tevent_req_data(req,
                                                struct ipa_srv_ad_acct_state);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
