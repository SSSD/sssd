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
#include "providers/ipa/ipa_id.h"
#include "providers/ad/ad_id.h"
#include "providers/ipa/ipa_subdomains.h"

static struct tevent_req *
ipa_srv_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct be_req *be_req,
                     struct sysdb_attrs *override_attrs,
                     struct be_acct_req *ar);
static errno_t
ipa_srv_ad_acct_recv(struct tevent_req *req, int *dp_error_out);

struct ipa_subdomain_account_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct be_req *be_req;
    struct be_acct_req *ar;

    bool ipa_server_mode;
    bool server_retry;
    int entry_type;
    const char *filter;
    int filter_type;
    struct sysdb_attrs *override_attrs;

    int dp_error;
};

static void ipa_subdomain_account_connected(struct tevent_req *subreq);
static void ipa_subdomain_account_got_override(struct tevent_req *subreq);
static void ipa_subdomain_account_done(struct tevent_req *subreq);
static errno_t ipa_subdomain_account_get_original_step(struct tevent_req *req,
                                                       struct be_acct_req *ar);

struct tevent_req *ipa_subdomain_account_send(TALLOC_CTX *memctx,
                                              struct tevent_context *ev,
                                              struct ipa_id_ctx *ipa_ctx,
                                              struct be_req *be_req,
                                              struct be_acct_req *ar)
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
    state->be_req = be_req;
    state->ar = ar;
    state->ipa_server_mode = dp_opt_get_bool(state->ipa_ctx->ipa_options->basic,
                                             IPA_SERVER_MODE);
    state->override_attrs = NULL;

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
    struct be_acct_req *ar;

    ret = ipa_get_ad_override_recv(subreq, &dp_error, state,
                                   &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
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

            ret = get_be_acct_req_for_sid(state,
                                        anchor + OVERRIDE_ANCHOR_SID_PREFIX_LEN,
                                        state->ar->domain,
                                        &ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_be_acct_req_for_sid failed.\n");
                goto fail;
            }

            if (state->ipa_server_mode
                    && (state->ar->entry_type & BE_REQ_TYPE_MASK)
                                                         == BE_REQ_INITGROUPS) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Switching back to BE_REQ_INITGROUPS.\n");
                ar->entry_type = BE_REQ_INITGROUPS;
                ar->filter_type = BE_FILTER_SECID;
                ar->attr_type = BE_ATTR_CORE;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported override anchor type [%s].\n", anchor);
            ret = EINVAL;
            goto fail;
        }
    } else {
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
                                                       struct be_acct_req *ar)
{
    struct ipa_subdomain_account_state *state = tevent_req_data(req,
                                            struct ipa_subdomain_account_state);
    struct tevent_req *subreq;

    if (state->ipa_server_mode) {
        subreq = ipa_srv_ad_acct_send(state, state->ev, state->ipa_ctx,
                                      state->be_req, state->override_attrs, ar);
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

    int dp_error;
};

static void ipa_get_subdom_acct_connected(struct tevent_req *subreq);
static void ipa_get_subdom_acct_done(struct tevent_req *subreq);

struct tevent_req *ipa_get_subdom_acct_send(TALLOC_CTX *memctx,
                                            struct tevent_context *ev,
                                            struct ipa_id_ctx *ipa_ctx,
                                            struct sysdb_attrs *override_attrs,
                                            struct be_acct_req *ar)
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

    switch (state->entry_type) {
        case BE_REQ_USER:
        case BE_REQ_GROUP:
        case BE_REQ_BY_SECID:
        case BE_REQ_USER_AND_GROUP:
        case BE_REQ_INITGROUPS:
            ret = EOK;
            break;
        default:
            ret = EINVAL;
            DEBUG(SSSDBG_OP_FAILURE, "Invalid sub-domain request type.\n");
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

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (state->entry_type == BE_REQ_INITGROUPS) {
        /* With V1 of the extdom plugin a user lookup will resolve the full
         * group membership of the user. */
        if (sdap_is_extension_supported(sdap_id_op_handle(state->op),
                                        EXOP_SID2NAME_V1_OID)) {
            state->entry_type = BE_REQ_USER;
        } else {
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
            req_input->inp.name = talloc_strdup(req_input, state->filter);
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

/* IPA lookup for server mode. Directly to AD. */
struct ipa_get_ad_acct_state {
    int dp_error;
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct be_req *be_req;
    struct be_acct_req *ar;
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
static struct ad_id_ctx *ipa_get_ad_id_ctx(struct ipa_id_ctx *ipa_ctx,
                                           struct sss_domain_info *dom);

static struct tevent_req *
ipa_get_ad_acct_send(TALLOC_CTX *mem_ctx,
                     struct tevent_context *ev,
                     struct ipa_id_ctx *ipa_ctx,
                     struct be_req *be_req,
                     struct sysdb_attrs *override_attrs,
                     struct be_acct_req *ar)
{
    errno_t ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_get_ad_acct_state *state;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx **clist;
    struct sdap_id_ctx *sdap_id_ctx;;
    struct ad_id_ctx *ad_id_ctx;

    req = tevent_req_create(mem_ctx, &state, struct ipa_get_ad_acct_state);
    if (req == NULL) return NULL;

    state->dp_error = -1;
    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->be_req = be_req;
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
        clist = ad_gc_conn_list(req, ad_id_ctx, state->obj_dom);
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

    subreq = ad_handle_acct_info_send(req, be_req, ar, sdap_id_ctx,
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

static errno_t
get_subdomain_homedir_of_user(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                              const char *fqname, uint32_t uid,
                              const char *original, const char **_homedir)
{
    errno_t ret;
    const char *name;
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

    ZERO_STRUCT(homedir_ctx);

    homedir_ctx.uid = uid;
    homedir_ctx.domain = dom->name;
    homedir_ctx.flatname = dom->flat_name;
    homedir_ctx.config_homedir_substr = dom->homedir_substr;
    homedir_ctx.original = original;
    ret = sss_parse_name_const(tmp_ctx, dom->names, fqname,
                               NULL, &name);
    if (ret != EOK) {
        goto done;
    }

    /* To be compatible with the old winbind based user lookups and IPA
     * clients the user name in the home directory path will be lower-case. */
    homedir_ctx.username = sss_tc_utf8_str_tolower(tmp_ctx, name);
    if (homedir_ctx.username == NULL) {
        ret = ENOMEM;
        goto done;
    }

    homedir = expand_homedir_template(tmp_ctx, dom->subdomain_homedir,
                                      &homedir_ctx);
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

    msg_el = ldb_msg_find_element(msg, SYSDB_OBJECTCLASS);
    if (msg_el == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_msg_find_element failed.\n");
        ret = ENOENT;
        goto done;
    }

    for (c = 0; c < msg_el->num_values; c++) {
        if (strncmp(SYSDB_USER_CLASS, (const char *)msg_el->values[c].data,
                    msg_el->values[c].length) == 0) {
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
        DEBUG(SSSDBG_OP_FAILURE, "UID for user [%s] is not known.\n",
                                  fqname);
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
                              struct be_acct_req *ar,
                              struct ldb_message **_msg)
{
    errno_t ret;
    uint32_t id;
    struct ldb_message *msg = NULL;
    struct ldb_result *res = NULL;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_UIDNUM,
                            SYSDB_SID_STR,
                            SYSDB_OBJECTCLASS,
                            SYSDB_UUID,
                            SYSDB_GHOST,
                            SYSDB_HOMEDIR,
                            NULL };
    char *name;

    if (ar->filter_type == BE_FILTER_SECID) {
        ret = sysdb_search_object_by_sid(mem_ctx, dom, ar->filter_value, attrs,
                                         &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make request to our cache: [%d]: [%s]\n",
                   ret, sss_strerror(ret));
            goto done;
        }

        *_msg = res->msgs[0];

        ret = EOK;
        goto done;
    } else if (ar->filter_type == BE_FILTER_UUID) {
        ret = sysdb_search_object_by_uuid(mem_ctx, dom, ar->filter_value, attrs,
                                          &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make request to our cache: [%d]: [%s]\n",
                   ret, sss_strerror(ret));
            goto done;
        }

        *_msg = res->msgs[0];

        ret = EOK;
        goto done;
    } else if (ar->filter_type == BE_FILTER_CERT) {
        ret = sysdb_search_object_by_cert(mem_ctx, dom, ar->filter_value, attrs,
                                          &res);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make request to our cache: [%d]: [%s]\n",
                   ret, sss_strerror(ret));
            goto done;
        }

        *_msg = res->msgs[0];

        ret = EOK;
        goto done;
    } else if (ar->filter_type == BE_FILTER_IDNUM) {
        errno = 0;
        id = strtouint32(ar->filter_value, NULL, 10);
        if (errno != 0) {
            ret = errno;
            DEBUG(SSSDBG_OP_FAILURE, "strtouint32 failed.\n");
            goto done;
        }

        switch (ar->entry_type & BE_REQ_TYPE_MASK) {
        case BE_REQ_GROUP:
            ret = sysdb_search_group_by_gid(mem_ctx, dom, id, attrs, &msg);
            break;
        case BE_REQ_INITGROUPS:
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:
            ret = sysdb_search_user_by_uid(mem_ctx, dom, id, attrs, &msg);
            if (ret == ENOENT && (ar->entry_type & BE_REQ_TYPE_MASK)
                                                     == BE_REQ_USER_AND_GROUP) {
                ret = sysdb_search_group_by_gid(mem_ctx, dom, id, attrs, &msg);
            }
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected entry type [%d].\n",
                                        (ar->entry_type & BE_REQ_TYPE_MASK));
            ret = EINVAL;
            goto done;
        }
    } else if (ar->filter_type == BE_FILTER_NAME) {
        name = sss_get_domain_name(mem_ctx, ar->filter_value, dom);
        if (name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_get_domain_name failed\n");
            ret = ENOMEM;
            goto done;
        }

        switch (ar->entry_type & BE_REQ_TYPE_MASK) {
        case BE_REQ_GROUP:
            ret = sysdb_search_group_by_name(mem_ctx, dom, name, attrs, &msg);
            break;
        case BE_REQ_INITGROUPS:
        case BE_REQ_USER:
        case BE_REQ_USER_AND_GROUP:
            ret = sysdb_search_user_by_name(mem_ctx, dom, name, attrs, &msg);
            if (ret == ENOENT && (ar->entry_type & BE_REQ_TYPE_MASK)
                                                     == BE_REQ_USER_AND_GROUP) {
                ret = sysdb_search_group_by_name(mem_ctx, dom, name,
                                                 attrs, &msg);
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

    if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to make request to our cache: [%d]: [%s]\n",
               ret, sss_strerror(ret));
        goto done;
    }

    *_msg = msg;

done:
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
    struct be_acct_req *ar;

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
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto fail;
        }

        ret = get_be_acct_req_for_sid(state, state->object_sid,
                                      state->obj_dom->name, &ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_be_acct_req_for_sid failed.\n");
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
            && entry_type != BE_REQ_BY_SECID) {
        tevent_req_done(req);
        return EOK;
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
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
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
    struct be_req *be_req;
    struct sysdb_attrs *override_attrs;
    struct be_acct_req *ar;

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
                     struct be_req *be_req,
                     struct sysdb_attrs *override_attrs,
                     struct be_acct_req *ar)
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
    state->be_req = be_req;
    state->override_attrs = override_attrs;
    state->ar = ar;
    state->retry = true;
    state->dp_error = DP_ERR_FATAL;
    state->be_ctx = be_req_get_be_ctx(state->be_req);

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
                                  state->be_req, state->override_attrs,
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
              "Sudomain lookup failed, will try to reset sudomain..\n");
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
    }

    DEBUG(SSSDBG_TRACE_FUNC, "Sudomain re-set, will retry lookup\n");
    be_fo_reset_svc(state->be_ctx, state->obj_dom->name);

    ret = ipa_srv_ad_acct_lookup_step(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to look up AD acct [%d]: %s\n", ret, sss_strerror(ret));
        state->dp_error = DP_ERR_FATAL;
        tevent_req_error(req, ret);
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
