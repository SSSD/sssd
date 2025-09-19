/*
    SSSD

    Authors:
        Stephen Gallagher <sgallagh@redhat.com>

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
#include "util/util.h"
#include "util/strtonum.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_id.h"
#include "providers/ad/ad_domain_info.h"
#include "providers/ad/ad_pac.h"
#include "providers/ldap/sdap_async_enum.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_async.h"

static bool ad_account_can_shortcut(struct sdap_idmap_ctx *idmap_ctx,
                                    struct sss_domain_info *domain,
                                    int filter_type,
                                    const char *filter_value)
{
    struct sss_domain_info *dom_head = NULL;
    struct sss_domain_info *sid_dom = NULL;
    enum idmap_error_code err;
    char *sid = NULL;
    const char *csid = NULL;
    uint32_t id;
    bool shortcut = false;
    errno_t ret;
    char *endptr;

    if (!sdap_idmap_domain_has_algorithmic_mapping(idmap_ctx, domain->name,
                                                   domain->domain_id)) {
        goto done;
    }

    switch (filter_type) {
    case BE_FILTER_IDNUM:
        /* convert value to ID */
        id = strtouint32(filter_value, &endptr, 10);
        if ((errno != 0) || *endptr || (filter_value == endptr)) {
            ret = errno ? errno : EINVAL;
            DEBUG(SSSDBG_MINOR_FAILURE, "Unable to convert filter value to "
                  "number [%d]: %s\n", ret, strerror(ret));
            goto done;
        }

        /* convert the ID to its SID equivalent */
        err = sss_idmap_unix_to_sid(idmap_ctx->map, id, &sid);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Mapping ID [%s] to SID failed: "
                  "[%s]\n", filter_value, idmap_error_string(err));
            /* assume id is from a different domain */
            shortcut = true;
            goto done;
        }
        /* fall through */
        SSS_ATTRIBUTE_FALLTHROUGH;
    case BE_FILTER_SECID:
        csid = sid == NULL ? filter_value : sid;

        dom_head = get_domains_head(domain);
        if (dom_head == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find domain head\n");
            goto done;
        }

        sid_dom = find_domain_by_sid(dom_head, csid);
        if (sid_dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "Invalid domain for SID:%s\n", csid);
            goto done;
        }

        if (strcasecmp(sid_dom->name, domain->name) != 0) {
            shortcut = true;
        }
        break;
    default:
        break;
    }

done:
    if (sid != NULL) {
        sss_idmap_free_sid(idmap_ctx->map, sid);
    }

    return shortcut;
}

struct ad_handle_acct_info_state {
    struct dp_id_data *ar;
    struct sdap_id_ctx *ctx;
    struct sdap_id_conn_ctx **conn;
    struct sdap_domain *sdom;
    size_t cindex;
    struct ad_options *ad_options;
    bool using_pac;

    int dp_error;
    const char *err;
};

static errno_t ad_handle_acct_info_step(struct tevent_req *req);
static void ad_handle_acct_info_done(struct tevent_req *subreq);

struct tevent_req *
ad_handle_acct_info_send(TALLOC_CTX *mem_ctx,
                         struct dp_id_data *ar,
                         struct sdap_id_ctx *ctx,
                         struct ad_options *ad_options,
                         struct sdap_domain *sdom,
                         struct sdap_id_conn_ctx **conn)
{
    struct tevent_req *req;
    struct ad_handle_acct_info_state *state;
    struct be_ctx *be_ctx = ctx->be;
    errno_t ret;
    bool shortcut;

    req = tevent_req_create(mem_ctx, &state, struct ad_handle_acct_info_state);
    if (req == NULL) {
        return NULL;
    }
    state->ar = ar;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->ad_options = ad_options;
    state->cindex = 0;

    /* Try to shortcut if this is ID or SID search and it belongs to
     * other domain range than is in ar->domain. */
    shortcut = ad_account_can_shortcut(ctx->opts->idmap_ctx,
                                       sdom->dom,
                                       ar->filter_type,
                                       ar->filter_value);
    if (shortcut) {
        DEBUG(SSSDBG_TRACE_FUNC, "This ID is from different domain\n");
        ret = EOK;
        goto immediate;
    }

    if (sss_domain_get_state(sdom->dom) == DOM_INACTIVE) {
        ret = ERR_SUBDOM_INACTIVE;
        goto immediate;
    }

    ret = ad_handle_acct_info_step(req);
    if (ret != EAGAIN) {
        goto immediate;
    }

    /* Lookup in progress */
    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, be_ctx->ev);
    return req;
}

static errno_t
ad_handle_acct_info_step(struct tevent_req *req)
{
    struct tevent_req *subreq = NULL;
    struct ad_handle_acct_info_state *state = tevent_req_data(req,
                                            struct ad_handle_acct_info_state);
    bool noexist_delete = false;
    struct ldb_message *msg;
    int ret;

    if (state->conn[state->cindex] == NULL) {
        return EOK;
    }

    if (state->conn[state->cindex+1] == NULL) {
        noexist_delete = true;
    }


    state->using_pac = false;
    if ((state->ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_INITGROUPS) {
        ret = check_if_pac_is_available(state, state->sdom->dom,
                                        state->ar, &msg);

        if (ret == EOK) {
            /* evaluate PAC */
            state->using_pac = true;
            subreq = ad_handle_pac_initgr_send(state, state->ctx->be,
                                               state->ar, state->ctx,
                                               state->sdom,
                                               state->conn[state->cindex],
                                               noexist_delete,
                                               msg);
            if (subreq == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "ad_handle_pac_initgr_send failed.\n");
                return ENOMEM;
            }

        }

        /* Fall through if there is no PAC or any other error */
    }

    if (subreq == NULL) {
        subreq = sdap_handle_acct_req_send(state, state->ctx->be,
                                           state->ar, state->ctx,
                                           state->sdom,
                                           state->conn[state->cindex],
                                           noexist_delete);
        if (subreq == NULL) {
            return ENOMEM;
        }
    }

    tevent_req_set_callback(subreq, ad_handle_acct_info_done, req);
    return EAGAIN;
}

static void
ad_handle_acct_info_done(struct tevent_req *subreq)
{
    errno_t ret;
    int dp_error;
    int sdap_err;
    const char *err;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_handle_acct_info_state *state = tevent_req_data(req,
                                            struct ad_handle_acct_info_state);

    if (state->using_pac) {
        ret = ad_handle_pac_initgr_recv(subreq, &dp_error, &err, &sdap_err);
    } else {
        ret = sdap_handle_acct_req_recv(subreq, &dp_error, &err, &sdap_err);
    }
    if (dp_error == DP_ERR_OFFLINE
        && state->conn[state->cindex+1] != NULL
        && state->conn[state->cindex]->ignore_mark_offline) {
         /* This is a special case: GC does not work.
          *  We need to Fall back to ldap
          */
        ret = EOK;
        sdap_err = ENOENT;
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        /* if GC was not used dp error should be set */
        state->dp_error = dp_error;
        state->err = err;

        goto fail;
    }

    if (sdap_err == EOK) {
        tevent_req_done(req);
        return;
    } else if (sdap_err != ENOENT) {
        ret = EIO;
        goto fail;
    }

    /* Ret is only ENOENT now. Try the next connection */
    state->cindex++;
    ret = ad_handle_acct_info_step(req);
    if (ret != EAGAIN) {
        /* No additional search in progress. Save the last
         * error status, we'll be returning it.
         */
        state->dp_error = dp_error;
        state->err = err;

        if (ret == EOK) {
            /* No more connections */
            tevent_req_done(req);
        } else {
            goto fail;
        }
        return;
    }

    /* Another lookup in progress */
    return;

fail:
    if (IS_SUBDOMAIN(state->sdom->dom)) {
        /* Deactivate subdomain on lookup errors instead of going
         * offline completely.
         * This is a stopgap, until our failover is per-domain,
         * not per-backend. Unfortunately, we can't rewrite the error
         * code on some reported codes only, because sdap_id_op code
         * encapsulated the failover as well..
         */
        ret = ERR_SUBDOM_INACTIVE;
    }
    tevent_req_error(req, ret);
    return;
}

errno_t
ad_handle_acct_info_recv(struct tevent_req *req,
                         int *_dp_error, const char **_err)
{
    struct ad_handle_acct_info_state *state = tevent_req_data(req,
                                            struct ad_handle_acct_info_state);

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    if (_err) {
        *_err = state->err;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct sdap_id_conn_ctx **
get_conn_list(TALLOC_CTX *mem_ctx, struct ad_id_ctx *ad_ctx,
              struct sss_domain_info *dom, struct dp_id_data *ar)
{
    struct sdap_id_conn_ctx **clist;

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
        clist = ad_user_conn_list(mem_ctx, ad_ctx, dom);
        break;
    case BE_REQ_BY_SECID:   /* by SID */
    case BE_REQ_USER_AND_GROUP: /* get SID */
    case BE_REQ_GROUP: /* group */
    case BE_REQ_INITGROUPS: /* init groups for user */
        clist = ad_gc_conn_list(mem_ctx, ad_ctx, dom);
        break;
    default:
        /* Requests for other object should only contact LDAP by default */
        clist = ad_ldap_conn_list(mem_ctx, ad_ctx, dom);
        break;
    }

    return clist;
}

struct ad_account_info_state {
    const char *err_msg;
    int dp_error;
};

static void ad_account_info_done(struct tevent_req *subreq);

struct tevent_req *
ad_account_info_send(TALLOC_CTX *mem_ctx,
                     struct be_ctx *be_ctx,
                     struct ad_id_ctx *id_ctx,
                     struct dp_id_data *data)
{
    struct sss_domain_info *domain = NULL;
    struct ad_account_info_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    struct sdap_id_conn_ctx **clist = NULL;
    struct sdap_id_ctx *sdap_id_ctx = NULL;
    struct sdap_domain *sdom;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_account_info_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    sdap_id_ctx = id_ctx->sdap_id_ctx;

    domain = be_ctx->domain;
    if (strcasecmp(data->domain, be_ctx->domain->name) != 0) {
        /* Subdomain request, verify subdomain. */
        domain = find_domain_by_name(be_ctx->domain, data->domain, true);
    }

    if (domain == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unknown domain\n");
        ret = EINVAL;
        goto immediately;
    }

    /* Determine whether to connect to GC, LDAP or try both. */
    clist = get_conn_list(state, id_ctx, domain, data);
    if (clist == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot create conn list\n");
        ret = EIO;
        goto immediately;
    }

    sdom = sdap_domain_get(sdap_id_ctx->opts, domain);
    if (sdom == NULL) {
        ret = EIO;
        goto immediately;
    }

    subreq = ad_handle_acct_info_send(state, data, sdap_id_ctx,
                                      id_ctx->ad_options, sdom, clist);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, ad_account_info_done, req);
    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void ad_account_info_done(struct tevent_req *subreq)
{
    struct ad_account_info_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_account_info_state);

    ret = ad_handle_acct_info_recv(subreq, &state->dp_error, &state->err_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ad_handle_acct_info_recv failed [%d]: %s\n",
              ret, sss_strerror(ret));
        /* The caller wouldn't fail either, just report the error up */
    }
    talloc_zfree(subreq);
    tevent_req_done(req);
}

errno_t ad_account_info_recv(struct tevent_req *req,
                             int *_dp_error,
                             const char **_err_msg)
{
    struct ad_account_info_state *state = NULL;

    state = tevent_req_data(req, struct ad_account_info_state);

    if (_err_msg != NULL) {
        *_err_msg = state->err_msg;
    }

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }


    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ad_account_info_handler_state {
    struct sss_domain_info *domain;
    struct dp_reply_std reply;
};

static void ad_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
ad_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct ad_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params)
{
    struct ad_account_info_handler_state *state;
    struct tevent_req *subreq;
    struct tevent_req *req;
    errno_t ret;


    req = tevent_req_create(mem_ctx, &state,
                            struct ad_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sdap_is_enum_request(data)) {
        DEBUG(SSSDBG_TRACE_LIBS, "Skipping enumeration on demand\n");
        ret = EOK;
        goto immediately;
    }

    subreq = ad_account_info_send(state, params->be_ctx, id_ctx, data);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }

    tevent_req_set_callback(subreq, ad_account_info_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ad_account_info_handler_done(struct tevent_req *subreq)
{
    struct ad_account_info_handler_state *state;
    struct tevent_req *req;
    const char *err_msg;
    int dp_error = DP_ERR_FATAL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_account_info_handler_state);

    ret = ad_account_info_recv(subreq, &dp_error, &err_msg);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, err_msg);
    tevent_req_done(req);
}

errno_t ad_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                     struct tevent_req *req,
                                     struct dp_reply_std *data)
{
    struct ad_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct ad_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}

static errno_t ad_get_account_domain_prepare_search(struct tevent_req *req);
static errno_t ad_get_account_domain_connect_retry(struct tevent_req *req);
static void ad_get_account_domain_connect_done(struct tevent_req *subreq);
static void ad_get_account_domain_search(struct tevent_req *req);
static void ad_get_account_domain_search_done(struct tevent_req *subreq);
static void ad_get_account_domain_evaluate(struct tevent_req *req);

struct ad_get_account_domain_state {
    struct tevent_context *ev;
    struct ad_id_ctx *id_ctx;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_domain *sdom;
    uint32_t entry_type;
    uint32_t filter_type;
    char *clean_filter;

    bool twopass;

    struct sdap_search_base **search_bases;
    size_t base_iter;
    const char *base_filter;
    char *filter;
    const char **attrs;
    int dp_error;
    struct dp_reply_std reply;
    struct sdap_id_op *op;
    struct sysdb_attrs **objects;
    size_t count;

    const char *found_domain_name;
};

struct tevent_req *
ad_get_account_domain_send(TALLOC_CTX *mem_ctx,
                           struct ad_id_ctx *id_ctx,
                           struct dp_get_acct_domain_data *data,
                           struct dp_req_params *params)
{
    struct ad_get_account_domain_state *state;
    struct tevent_req *req;
    errno_t ret;
    bool use_id_mapping;
    struct sss_domain_info *domain;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_get_account_domain_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }
    state->ev = params->ev;
    state->id_ctx = id_ctx;
    state->sdap_id_ctx = id_ctx->sdap_id_ctx;
    state->entry_type = data->entry_type & BE_REQ_TYPE_MASK;
    state->filter_type = data->filter_type;
    state->attrs = talloc_array(state, const char *, 2);
    if (state->attrs == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    state->attrs[0] = "objectclass";
    state->attrs[1] = NULL;

    if (sss_domain_is_mpg(params->be_ctx->domain) == true
            || state->entry_type == BE_REQ_USER_AND_GROUP) {
        state->twopass = true;
        if (state->entry_type == BE_REQ_USER_AND_GROUP) {
            state->entry_type = BE_REQ_GROUP;
        }
    }

    /* SID lookup does not require communication with backend */
    if (state->entry_type == BE_REQ_BY_SECID) {
        domain = find_domain_by_sid(params->domain, data->filter_value);
        if (domain == NULL) {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "SID %s does not fit into any domain\n", data->filter_value);
            dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ERR_NOT_FOUND, NULL);
        } else {
            DEBUG(SSSDBG_TRACE_INTERNAL,
                  "SID %s fits into domain %s\n", data->filter_value, domain->name);
            dp_reply_std_set(&state->reply, DP_ERR_DECIDE, EOK, domain->name);
        }
        tevent_req_done(req);
        tevent_req_post(req, params->ev);
        return req;
    }

    /* The get-account-domain request only works with GC */
    if (dp_opt_get_bool(id_ctx->ad_options->basic, AD_ENABLE_GC) == false) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "Global catalog support is not enabled, "
              "cannot locate the account domain\n");
        ret = ERR_GET_ACCT_DOM_NOT_SUPPORTED;
        goto immediately;
    }

    state->sdom = sdap_domain_get(id_ctx->sdap_id_ctx->opts,
                                  params->be_ctx->domain);
    if (state->sdom == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find sdap_domain\n");
        ret = EIO;
        goto immediately;
    }

    /* Currently we only support locating the account domain
     * if ID mapping is disabled. With ID mapping enabled, we can
     * already shortcut the 'real' ID request
     */
    use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                        state->sdap_id_ctx->opts->idmap_ctx,
                                        state->sdom->dom->name,
                                        state->sdom->dom->domain_id);
    if (use_id_mapping == true) {
        DEBUG(SSSDBG_CONF_SETTINGS,
              "No point in locating domain with GC if ID-mapping "
              "is enabled\n");
        ret = ERR_GET_ACCT_DOM_NOT_SUPPORTED;
        goto immediately;
    }

    ret = sss_filter_sanitize(state, data->filter_value, &state->clean_filter);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Cannot sanitize filter [%d]: %s\n", ret, sss_strerror(ret));
        goto immediately;
    }

    ret = ad_get_account_domain_prepare_search(req);
    if (ret != EOK) {
        goto immediately;
    }

    /* FIXME - should gc_ctx always default to ignore_offline on creation
     * time rather than setting the flag on first use?
     */
    id_ctx->gc_ctx->ignore_mark_offline = true;
    state->op = sdap_id_op_create(state, id_ctx->gc_ctx->conn_cache);
    if (state->op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto immediately;
    }

    ret = ad_get_account_domain_connect_retry(req);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Connection error");
        goto immediately;
    }

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static errno_t ad_get_account_domain_prepare_search(struct tevent_req *req)
{
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    const char *attr_name = NULL;
    const char *objectclass = NULL;

    switch (state->entry_type) {
    case BE_REQ_USER:
        state->search_bases = state->sdom->user_search_bases;
        attr_name = state->sdap_id_ctx->opts->user_map[SDAP_AT_USER_UID].name;
        objectclass = state->sdap_id_ctx->opts->user_map[SDAP_OC_USER].name;
        break;
    case BE_REQ_GROUP:
        state->search_bases = state->sdom->group_search_bases;
        attr_name = state->sdap_id_ctx->opts->group_map[SDAP_AT_GROUP_GID].name;
        objectclass = state->sdap_id_ctx->opts->group_map[SDAP_OC_GROUP].name;
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Unsupported request type %X\n",
              state->entry_type & BE_REQ_TYPE_MASK);
        return EINVAL;
    }

    if (state->search_bases == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to prepare search: missing search_bases\n");
        return EINVAL;
    }

    switch (state->filter_type) {
    case BE_FILTER_IDNUM:
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Unsupported filter type %X\n", state->filter_type);
        return EINVAL;
    }

    talloc_zfree(state->base_filter);
    state->base_filter = talloc_asprintf(state,
                                         "(&(%s=%s)(objectclass=%s))",
                                         attr_name,
                                         state->clean_filter,
                                         objectclass);
    if (state->base_filter == NULL) {
        return ENOMEM;
    }

    return EOK;
}

static errno_t ad_get_account_domain_connect_retry(struct tevent_req *req)
{
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    struct tevent_req *subreq;
    errno_t ret;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (subreq == NULL) {
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ad_get_account_domain_connect_done, req);
    return ret;
}

static void ad_get_account_domain_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    int dp_error = DP_ERR_FATAL;
    errno_t ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    ad_get_account_domain_search(req);
}

static void ad_get_account_domain_search(struct tevent_req *req)
{
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    struct tevent_req *subreq;

    talloc_zfree(state->filter);
    state->filter = sdap_combine_filters(state, state->base_filter,
                        state->search_bases[state->base_iter]->filter);
    if (state->filter == NULL) {
        tevent_req_error(req, ENOMEM);
        return;
    }

    subreq = sdap_get_generic_send(state, state->ev, state->sdap_id_ctx->opts,
                                   sdap_id_op_handle(state->op),
                                   "",
                                   LDAP_SCOPE_SUBTREE,
                                   state->filter,
                                   state->attrs, NULL, 0,
                                   dp_opt_get_int(state->sdap_id_ctx->opts->basic,
                                                  SDAP_SEARCH_TIMEOUT),
                                   false);

    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        tevent_req_error(req, EIO);
        return;
    }

    tevent_req_set_callback(subreq, ad_get_account_domain_search_done, req);
}

static void ad_get_account_domain_search_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    size_t count;
    struct sysdb_attrs **objects;
    errno_t ret;

    ret = sdap_get_generic_recv(subreq, state,
                                &count, &objects);
    talloc_zfree(subreq);
    if (ret) {
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC,
          "Search returned %zu results.\n", count);

    if (count > 0) {
        size_t copied;

        state->objects =
                talloc_realloc(state,
                               state->objects,
                               struct sysdb_attrs *,
                               state->count + count + 1);
        if (!state->objects) {
            tevent_req_error(req, ENOMEM);
            return;
        }

        copied = sdap_steal_objects_in_dom(state->sdap_id_ctx->opts,
                                           state->objects,
                                           state->count,
                                           NULL,
                                           objects, count,
                                           false);

        state->count += copied;
        state->objects[state->count] = NULL;
    }

    /* Even though we search with an empty search base (=across all domains)
     * the reason we iterate over search bases is that the search bases can
     * also contain a filter which might restrict the IDs we find
     */
    state->base_iter++;
    if (state->search_bases[state->base_iter]) {
        /* There are more search bases to try */
        ad_get_account_domain_search(req);
        return;
    }

    /* No more searches, evaluate results */
    ad_get_account_domain_evaluate(req);
}

static void ad_get_account_domain_evaluate(struct tevent_req *req)
{
    struct ad_get_account_domain_state *state = tevent_req_data(req,
                                          struct ad_get_account_domain_state);
    struct sss_domain_info *obj_dom;
    errno_t ret;

    if (state->count == 0) {
        if (state->twopass
                && state->entry_type != BE_REQ_USER) {
            DEBUG(SSSDBG_TRACE_FUNC, "Retrying search\n");

            state->entry_type = BE_REQ_USER;
            state->base_iter = 0;
            ret = ad_get_account_domain_prepare_search(req);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot retry search\n");
                tevent_req_error(req, ret);
                return;
            }

            ad_get_account_domain_search(req);
            return;
        }

        DEBUG(SSSDBG_TRACE_FUNC, "Not found\n");
        dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ERR_NOT_FOUND, NULL);
        tevent_req_done(req);
        return;
    } else if (state->count > 1) {
        /* FIXME: If more than one entry was found, return error for now
         * as the account requsts have no way of returning multiple
         * messages back until we switch to the rdp_* requests
         * from the responder side
         */
        DEBUG(SSSDBG_OP_FAILURE, "Multiple entries found, error!\n");
        dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ERANGE, NULL);
        tevent_req_done(req);
        return;
    }

    /* Exactly one entry was found */
    obj_dom = sdap_get_object_domain(state->sdap_id_ctx->opts,
                                     state->objects[0],
                                     state->sdom->dom);
    if (obj_dom == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not match entry with domain!\n");
        dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ERR_NOT_FOUND, NULL);
        tevent_req_done(req);
        return;
    }

    DEBUG(SSSDBG_TRACE_INTERNAL,
          "Found object in domain %s\n", obj_dom->name);
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, EOK, obj_dom->name);
    tevent_req_done(req);
}

errno_t ad_get_account_domain_recv(TALLOC_CTX *mem_ctx,
                                   struct tevent_req *req,
                                   struct dp_reply_std *data)
{
    struct ad_get_account_domain_state *state = NULL;

    state = tevent_req_data(req, struct ad_get_account_domain_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
