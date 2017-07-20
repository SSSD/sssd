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

static void
disable_gc(struct ad_options *ad_options)
{
    errno_t ret;

    if (dp_opt_get_bool(ad_options->basic, AD_ENABLE_GC) == false) {
        return;
    }

    DEBUG(SSSDBG_IMPORTANT_INFO, "POSIX attributes were requested "
          "but are not present on the server side. Global Catalog "
          "lookups will be disabled\n");

    ret = dp_opt_set_bool(ad_options->basic,
                          AD_ENABLE_GC, false);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
                "Could not turn off GC support\n");
        /* Not fatal */
    }
}

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

    if (!sdap_idmap_domain_has_algorithmic_mapping(idmap_ctx, domain->name,
                                                   domain->domain_id)) {
        goto done;
    }

    switch (filter_type) {
    case BE_FILTER_IDNUM:
        /* convert value to ID */
        errno = 0;
        id = strtouint32(filter_value, NULL, 10);
        if (errno != 0) {
            ret = errno;
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
    } else if (sdap_err == ERR_NO_POSIX) {
        disable_gc(state->ad_options);
    } else if (sdap_err != ENOENT) {
        ret = EIO;
        goto fail;
    }

    /* Ret is only ENOENT or ERR_NO_POSIX now. Try the next connection */
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
        clist = ad_user_conn_list(ad_ctx, dom);
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
    struct sdap_id_conn_ctx **clist;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sss_domain_info *domain;
    struct sdap_domain *sdom;
    struct tevent_req *subreq;
    struct tevent_req *req;
    struct be_ctx *be_ctx;
    errno_t ret;

    sdap_id_ctx = id_ctx->sdap_id_ctx;
    be_ctx = params->be_ctx;

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

    domain = be_ctx->domain;
    if (strcasecmp(data->domain, be_ctx->domain->name) != 0) {
        /* Subdomain request, verify subdomain. */
        domain = find_domain_by_name(be_ctx->domain, data->domain, true);
    }

    if (domain == NULL) {
        ret = EINVAL;
        goto immediately;
    }

    /* Determine whether to connect to GC, LDAP or try both. */
    clist = get_conn_list(state, id_ctx, domain, data);
    if (clist == NULL) {
        ret = EIO;
        goto immediately;
    }

    sdom = sdap_domain_get(sdap_id_ctx->opts, domain);
    if (sdom == NULL) {
        ret = EIO;
        goto immediately;
    }

    state->domain = sdom->dom;

    subreq = ad_handle_acct_info_send(state, data, sdap_id_ctx,
                                      id_ctx->ad_options, sdom, clist);
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
    int dp_error;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_account_info_handler_state);

    ret = ad_handle_acct_info_recv(subreq, &dp_error, &err_msg);
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

struct ad_enumeration_state {
    struct ad_id_ctx *id_ctx;
    struct ldap_enum_ctx *ectx;
    struct sdap_id_op *sdap_op;
    struct tevent_context *ev;

    const char *realm;
    struct sdap_domain *sdom;
    struct sdap_domain *sditer;
};

static void ad_enumeration_conn_done(struct tevent_req *subreq);
static void ad_enumeration_master_done(struct tevent_req *subreq);
static errno_t ad_enum_sdom(struct tevent_req *req, struct sdap_domain *sd,
                            struct ad_id_ctx *id_ctx);
static void ad_enumeration_done(struct tevent_req *subreq);

struct tevent_req *
ad_enumeration_send(TALLOC_CTX *mem_ctx,
                    struct tevent_context *ev,
                    struct be_ctx *be_ctx,
                    struct be_ptask *be_ptask,
                    void *pvt)
{
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ad_enumeration_state *state;
    struct ldap_enum_ctx *ectx;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_enumeration_state);
    if (req == NULL) return NULL;

    ectx = talloc_get_type(pvt, struct ldap_enum_ctx);
    if (ectx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot retrieve ldap_enum_ctx!\n");
        ret = EFAULT;
        goto fail;
    }

    state->ectx = ectx;
    state->ev = ev;
    state->sdom = ectx->sdom;
    state->sditer = state->sdom;
    state->id_ctx = talloc_get_type(ectx->pvt, struct ad_id_ctx);

    state->realm = dp_opt_get_cstring(state->id_ctx->ad_options->basic,
                                      AD_KRB5_REALM);
    if (state->realm == NULL) {
        DEBUG(SSSDBG_CONF_SETTINGS, "Missing realm\n");
        ret = EINVAL;
        goto fail;
    }

    state->sdap_op = sdap_id_op_create(state,
                                       state->id_ctx->ldap_ctx->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto fail;
    }
    tevent_req_set_callback(subreq, ad_enumeration_conn_done, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void
ad_enumeration_conn_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_enumeration_state *state = tevent_req_data(req,
                                                 struct ad_enumeration_state);
    int ret, dp_error;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        if (dp_error == DP_ERR_OFFLINE) {
            DEBUG(SSSDBG_TRACE_FUNC,
                  "Backend is marked offline, retry later!\n");
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Domain enumeration failed to connect to " \
                   "LDAP server: (%d)[%s]\n", ret, strerror(ret));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = ad_master_domain_send(state, state->ev,
                                   state->id_ctx->ldap_ctx,
                                   state->sdap_op,
                                   state->sdom->dom->name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_master_domain_send failed.\n");
        tevent_req_error(req, ret);
        return;
    }
    tevent_req_set_callback(subreq, ad_enumeration_master_done, req);
}

static void
ad_enumeration_master_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_enumeration_state *state = tevent_req_data(req,
                                                struct ad_enumeration_state);
    char *flat_name;
    char *master_sid;
    char *forest;

    ret = ad_master_domain_recv(subreq, state,
                                &flat_name, &master_sid, NULL, &forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot retrieve master domain info\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_master_domain_add_info(state->sdom->dom, state->realm,
                                       flat_name, master_sid, forest, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Cannot save master domain info\n");
        tevent_req_error(req, ret);
        return;
    }

    ret = ad_enum_sdom(req, state->sdom, state->id_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
                "Could not enumerate domain %s\n", state->sdom->dom->name);
        tevent_req_error(req, ret);
        return;
    }

    /* Execution will resume in ad_enumeration_done */
}

static errno_t
ad_enum_sdom(struct tevent_req *req,
             struct sdap_domain *sd,
             struct ad_id_ctx *id_ctx)
{
    struct sdap_id_conn_ctx *user_conn;
    struct tevent_req *subreq;
    struct ad_enumeration_state *state = tevent_req_data(req,
                                                struct ad_enumeration_state);

    if (dp_opt_get_bool(id_ctx->ad_options->basic, AD_ENABLE_GC)) {
        user_conn = id_ctx->gc_ctx;
    } else {
        user_conn = id_ctx->ldap_ctx;
    }

    /* Groups are searched for in LDAP, users in GC. Services (if present,
     * which is unlikely in AD) from LDAP as well
     */
    subreq = sdap_dom_enum_ex_send(state, state->ev,
                                   id_ctx->sdap_id_ctx,
                                   sd,
                                   user_conn,         /* Users    */
                                   id_ctx->ldap_ctx,  /* Groups   */
                                   id_ctx->ldap_ctx); /* Services */
    if (subreq == NULL) {
        /* The ptask API will reschedule the enumeration on its own on
         * failure */
        DEBUG(SSSDBG_OP_FAILURE,
              "Failed to schedule enumeration, retrying later!\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ad_enumeration_done, req);

    return EOK;
}

static errno_t ad_enum_cross_dom_members(struct sdap_options *opts,
                                         struct sss_domain_info *dom);

static void
ad_enumeration_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_enumeration_state *state = tevent_req_data(req,
                                                struct ad_enumeration_state);

    ret = sdap_dom_enum_ex_recv(subreq);
    talloc_zfree(subreq);
    if (ret == ERR_NO_POSIX) {
        /* Retry enumerating the same domain again, this time w/o
         * connecting to GC
         */
        disable_gc(state->id_ctx->ad_options);
        ret = ad_enum_sdom(req, state->sditer, state->id_ctx);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                "Could not retry domain %s\n", state->sditer->dom->name);
            tevent_req_error(req, ret);
            return;
        }

        /* Execution will resume in ad_enumeration_done */
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not enumerate domain %s\n", state->sditer->dom->name);
        tevent_req_error(req, ret);
        return;
    }

    do {
        state->sditer = state->sditer->next;
    } while (state->sditer &&
             state->sditer->dom->enumerate == false);

    if (state->sditer != NULL) {
        ret = ad_enum_sdom(req, state->sditer, state->sditer->pvt);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Could not enumerate domain %s\n",
                  state->sditer->dom->name);
            tevent_req_error(req, ret);
            return;
        }

        /* Execution will resume in ad_enumeration_done */
        return;
    }

    /* No more subdomains to enumerate. Check if we need to fixup
     * cross-domain membership
     */
    if (state->sditer != state->sdom) {
        /* We did enumerate at least one subdomain. Walk the subdomains
         * and fixup members for each of them
         */
        for (state->sditer = state->sdom;
             state->sditer;
             state->sditer = state->sditer->next) {
            ret = ad_enum_cross_dom_members(state->id_ctx->ad_options->id,
                                            state->sditer->dom);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Could not check cross-domain "
                      "memberships for %s, group memberships might be "
                      "incomplete!\n", state->sdom->dom->name);
                continue;
            }
        }
    }

    tevent_req_done(req);
}

static errno_t ad_group_extra_members(TALLOC_CTX *mem_ctx,
                                      const struct ldb_message *group,
                                      struct sss_domain_info *dom,
                                      char ***_group_only);
static errno_t ad_group_add_member(struct sdap_options *opts,
                                   struct sss_domain_info *group_domain,
                                   struct ldb_dn *group_dn,
                                   const char *member);

static errno_t
ad_enum_cross_dom_members(struct sdap_options *opts,
                          struct sss_domain_info *dom)
{
    errno_t ret;
    errno_t sret;
    char *filter;
    TALLOC_CTX *tmp_ctx;
    const char *attrs[] = {
            SYSDB_NAME,
            SYSDB_MEMBER,
            SYSDB_ORIG_MEMBER,
            NULL
    };
    size_t count, i, mi;
    struct ldb_message **msgs;
    bool in_transaction = false;
    char **group_only;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    ret = sysdb_transaction_start(dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to start transaction\n");
        goto done;
    }
    in_transaction = true;

    filter = talloc_asprintf(tmp_ctx, "(%s=*)", SYSDB_NAME);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_groups(tmp_ctx, dom, filter, attrs, &count, &msgs);
    if (ret != EOK) {
        goto done;
    }

    for (i = 0; i < count; i++) {
        ret = ad_group_extra_members(tmp_ctx, msgs[i], dom, &group_only);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Failed to check extra members\n");
            continue;
        } else if (group_only == NULL) {
            DEBUG(SSSDBG_TRACE_INTERNAL, "No extra members\n");
            continue;
        }

        /* Group has extra members */
        for (mi = 0; group_only[mi]; mi++) {
            ret = ad_group_add_member(opts, dom, msgs[i]->dn, group_only[mi]);
            if (ret != EOK) {
                DEBUG(SSSDBG_MINOR_FAILURE, "Failed to add [%s]: %s\n",
                      group_only[mi], strerror(ret));
                continue;
            }
        }

        talloc_zfree(group_only);
    }

    ret = sysdb_transaction_commit(dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Failed to commit transaction\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(dom->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Could not cancel transaction\n");
        }
    }
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ad_group_stored_orig_members(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                             struct ldb_dn *dn, char ***_odn_list);

static errno_t
ad_group_extra_members(TALLOC_CTX *mem_ctx, const struct ldb_message *group,
                       struct sss_domain_info *dom, char ***_group_only)
{
    TALLOC_CTX *tmp_ctx;
    struct ldb_message_element *m, *om;
    const char *name;
    errno_t ret;
    char **sysdb_odn_list;
    const char **group_odn_list;
    char **group_only = NULL;

    if (_group_only == NULL) return EINVAL;
    *_group_only = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    om = ldb_msg_find_element(group, SYSDB_ORIG_MEMBER);
    m = ldb_msg_find_element(group, SYSDB_MEMBER);
    name = ldb_msg_find_attr_as_string(group, SYSDB_NAME, NULL);
    if (name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "A group with no name!\n");
        ret = EFAULT;
        goto done;
    }

    if (om == NULL || om->num_values == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "Group %s has no original members\n", name);
        ret = EOK;
        goto done;
    }

    if (m == NULL || (m->num_values < om->num_values)) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "Group %s has %d members but %d original members\n",
               name, m ? m->num_values : 0, om->num_values);

        /* Get the list of originalDN attributes that are already
         * linked to the group
         */
        ret = ad_group_stored_orig_members(tmp_ctx, dom, group->dn,
                                           &sysdb_odn_list);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not retrieve list of original members for %s\n",
                  name);
            goto done;
        }

        /* Get the list of original DN attributes the group had in AD */
        group_odn_list = sss_ldb_el_to_string_list(tmp_ctx, om);
        if (group_odn_list == NULL) {
            ret = EFAULT;
            goto done;
        }

        /* Compare the two lists */
        ret = diff_string_lists(tmp_ctx, discard_const(group_odn_list),
                                sysdb_odn_list, &group_only, NULL, NULL);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Could not compare lists of members for %s\n", name);
            goto done;
        }
    }

    ret = EOK;
    *_group_only = talloc_steal(mem_ctx, group_only);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ad_group_stored_orig_members(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                             struct ldb_dn *dn, char ***_odn_list)
{
    errno_t ret;
    TALLOC_CTX *tmp_ctx;
    size_t m_count, i;
    struct ldb_message **members;
    const char *attrs[] = {
            SYSDB_NAME,
            SYSDB_ORIG_DN,
            NULL
    };
    char **odn_list;
    const char *odn;
    size_t oi;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    /* Get all entries member element points to */
    ret = sysdb_asq_search(tmp_ctx, dom, dn, NULL, SYSDB_MEMBER,
                           attrs, &m_count, &members);
    if (ret != EOK) {
        goto done;
    }

    odn_list = talloc_zero_array(tmp_ctx, char *, m_count + 1);
    if (odn_list == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* Get a list of their original DNs */
    oi = 0;
    for (i = 0; i < m_count; i++) {
        odn = ldb_msg_find_attr_as_string(members[i], SYSDB_ORIG_DN, NULL);
        if (odn == NULL) {
            continue;
        }

        odn_list[oi] = talloc_strdup(odn_list, odn);
        if (odn_list[oi] == NULL) {
            ret = ENOMEM;
            goto done;
        }
        oi++;
        DEBUG(SSSDBG_TRACE_INTERNAL, "Member %s already in sysdb\n", odn);
    }

    ret = EOK;
    *_odn_list = talloc_steal(mem_ctx, odn_list);
done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ad_group_add_member(struct sdap_options *opts,
                    struct sss_domain_info *group_domain,
                    struct ldb_dn *group_dn,
                    const char *member)
{
    struct sdap_domain *sd;
    struct ldb_dn *base_dn;
    TALLOC_CTX *tmp_ctx;
    errno_t ret;
    const char *mem_filter;
    size_t msgs_count;
    struct ldb_message **msgs;

    /* This member would be from a different domain */
    sd = sdap_domain_get_by_dn(opts, member);
    if (sd == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE, "No matching domain for %s\n", member);
        return ENOENT;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) return ENOMEM;

    mem_filter = talloc_asprintf(tmp_ctx, "(%s=%s)",
                                 SYSDB_ORIG_DN, member);
    if (mem_filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_domain_dn(tmp_ctx, sd->dom);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, sd->dom->sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, mem_filter, NULL,
                             &msgs_count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC, "No member [%s] in sysdb\n", member);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }
    DEBUG(SSSDBG_TRACE_INTERNAL, "[%s] found in sysdb\n", member);

    if (msgs_count != 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
               "Search by orig DN returned %zd results!\n", msgs_count);
        ret = EFAULT;
        goto done;
    }

    ret = sysdb_mod_group_member(group_domain, msgs[0]->dn, group_dn, SYSDB_MOD_ADD);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Could not add [%s] as a member of [%s]\n",
              ldb_dn_get_linearized(msgs[0]->dn),
              ldb_dn_get_linearized(group_dn));
        goto done;
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t
ad_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

