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
#include "providers/ldap/sdap_async_enum.h"
#include "providers/ldap/sdap_idmap.h"

struct ad_handle_acct_info_state {
    struct be_req *breq;
    struct be_acct_req *ar;
    struct sdap_id_ctx *ctx;
    struct sdap_id_conn_ctx **conn;
    struct sdap_domain *sdom;
    size_t cindex;

    int dp_error;
    const char *err;
};

static errno_t ad_handle_acct_info_step(struct tevent_req *req);
static void ad_handle_acct_info_done(struct tevent_req *subreq);

struct tevent_req *
ad_handle_acct_info_send(TALLOC_CTX *mem_ctx,
                         struct be_req *breq,
                         struct be_acct_req *ar,
                         struct sdap_id_ctx *ctx,
                         struct sdap_domain *sdom,
                         struct sdap_id_conn_ctx **conn)
{
    struct tevent_req *req;
    struct ad_handle_acct_info_state *state;
    struct be_ctx *be_ctx = be_req_get_be_ctx(breq);
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ad_handle_acct_info_state);
    if (req == NULL) {
        return NULL;
    }
    state->breq = breq;
    state->ar = ar;
    state->ctx = ctx;
    state->sdom = sdom;
    state->conn = conn;
    state->cindex = 0;

    ret = ad_handle_acct_info_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, be_ctx->ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, be_ctx->ev);
    }

    /* Lookup in progress */
    return req;
}

static errno_t
ad_handle_acct_info_step(struct tevent_req *req)
{
    struct tevent_req *subreq;
    struct ad_handle_acct_info_state *state = tevent_req_data(req,
                                            struct ad_handle_acct_info_state);
    bool noexist_delete = false;

    if (state->conn[state->cindex] == NULL) {
        return EOK;
    }

    if (state->conn[state->cindex+1] == NULL) {
        noexist_delete = true;
    }

    subreq = sdap_handle_acct_req_send(state, state->breq,
                                       state->ar, state->ctx,
                                       state->sdom,
                                       state->conn[state->cindex],
                                       noexist_delete);
    if (req == NULL) {
        return ENOMEM;
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

    ret = sdap_handle_acct_req_recv(subreq, &dp_error, &err, &sdap_err);
    if (dp_error == DP_ERR_OFFLINE
        && state->conn[state->cindex]->ignore_mark_offline) {
         /* This is a special case: GC does not work.
          *  We need to Fall back to ldap
          */
        ret = EOK;
        sdap_err = ENOENT;
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    if (sdap_err == EOK) {
        tevent_req_done(req);
        return;
    } else if (sdap_err != ENOENT) {
        tevent_req_error(req, EIO);
        return;
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
            tevent_req_error(req, ret);
        }
        return;
    }

    /* Another lookup in progress */
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
get_conn_list(struct be_req *breq, struct ad_id_ctx *ad_ctx,
              struct sss_domain_info *dom, struct be_acct_req *ar)
{
    struct sdap_id_conn_ctx **clist;

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER: /* user */
    case BE_REQ_BY_SECID:   /* by SID */
    case BE_REQ_USER_AND_GROUP: /* get SID */
    case BE_REQ_GROUP: /* group */
    case BE_REQ_INITGROUPS: /* init groups for user */
        clist = ad_gc_conn_list(breq, ad_ctx, dom);
        if (clist == NULL) return NULL;
        break;

    default:
        /* Requests for other object should only contact LDAP by default */
        clist = talloc_zero_array(breq, struct sdap_id_conn_ctx *, 2);
        if (clist == NULL) return NULL;

        clist[0] = ad_ctx->ldap_ctx;
        clist[1] = NULL;
        break;
    }

    return clist;
}

static errno_t ad_account_can_shortcut(struct be_ctx *be_ctx,
                                       struct sdap_idmap_ctx *idmap_ctx,
                                       int filter_type,
                                       const char *filter_value,
                                       const char *filter_domain,
                                       bool *_shortcut)
{
    struct sss_domain_info *domain = be_ctx->domain;
    struct sss_domain_info *req_dom = NULL;
    enum idmap_error_code err;
    char *sid = NULL;
    const char *csid = NULL;
    uint32_t id;
    bool shortcut = false;
    errno_t ret;

    if (!sdap_idmap_domain_has_algorithmic_mapping(idmap_ctx, domain->name,
                                                   domain->domain_id)) {
        shortcut = false;
        ret = EOK;
        goto done;
    }

    switch (filter_type) {
    case BE_FILTER_IDNUM:
        /* convert value to ID */
        errno = 0;
        id = strtouint32(filter_value, NULL, 10);
        if (errno != 0) {
            ret = errno;
            goto done;
        }

        /* convert the ID to its SID equivalent */
        err = sss_idmap_unix_to_sid(idmap_ctx->map, id, &sid);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_MINOR_FAILURE, ("Mapping ID [%s] to SID failed: "
                  "[%s]\n", filter_value, idmap_error_string(err)));
            ret = EIO;
            goto done;
        }
        /* fall through */
    case BE_FILTER_SECID:
        csid = sid == NULL ? filter_value : sid;

        req_dom = find_subdomain_by_sid(domain, csid);
        if (req_dom == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("Invalid domain\n"));
            ret = ERR_DOMAIN_NOT_FOUND;
            goto done;
        }

        if (strcasecmp(req_dom->name, filter_domain) != 0) {
            shortcut = true;
        } else {
            shortcut = false;
        }
        break;
    default:
        shortcut = false;
        break;
    }

    ret = EOK;

done:
    if (sid != NULL) {
        sss_idmap_free_sid(idmap_ctx->map, sid);
    }

    if (ret == EOK) {
        *_shortcut = shortcut;
    }

    return ret;
}

static void ad_account_info_complete(struct tevent_req *req);

void
ad_account_info_handler(struct be_req *be_req)
{
    struct ad_id_ctx *ad_ctx;
    struct be_acct_req *ar;
    struct sdap_id_ctx *sdap_id_ctx;
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);
    struct tevent_req *req;
    struct sss_domain_info *dom;
    struct sdap_domain *sdom;
    struct sdap_id_conn_ctx **clist;
    bool shortcut;
    errno_t ret;

    ad_ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                             struct ad_id_ctx);
    ar = talloc_get_type(be_req_get_data(be_req), struct be_acct_req);
    sdap_id_ctx = ad_ctx->sdap_id_ctx;

    if (be_is_offline(be_ctx)) {
        return be_req_terminate(be_req, DP_ERR_OFFLINE, EAGAIN, "Offline");
    }

    /* Try to shortcut if this is ID or SID search and it belongs to
     * other domain range than is in ar->domain. */
    ret = ad_account_can_shortcut(be_ctx, sdap_id_ctx->opts->idmap_ctx,
                                  ar->filter_type, ar->filter_value,
                                  ar->domain, &shortcut);
    if (ret != EOK) {
        goto fail;
    }

    if (shortcut) {
        DEBUG(SSSDBG_TRACE_FUNC, ("This ID is from different domain\n"));
        be_req_terminate(be_req, DP_ERR_OK, EOK, NULL);
        return;
    }

    dom = be_ctx->domain;
    if (strcasecmp(ar->domain, be_ctx->domain->name) != 0) {
        /* Subdomain request, verify subdomain */
        dom = find_subdomain_by_name(be_ctx->domain, ar->domain, true);
    }

    if (dom == NULL) {
        ret = EINVAL;
        goto fail;
    }

    /* Determine whether to connect to GC, LDAP or try both */
    clist = get_conn_list(be_req, ad_ctx, dom, ar);
    if (clist == NULL) {
        ret = EIO;
        goto fail;
    }

    sdom = sdap_domain_get(sdap_id_ctx->opts, dom);
    if (sdom == NULL) {
        ret = EIO;
        goto fail;
    }

    req = ad_handle_acct_info_send(be_req, be_req, ar, sdap_id_ctx,
                                   sdom, clist);
    if (req == NULL) {
        ret = ENOMEM;
        goto fail;
    }
    tevent_req_set_callback(req, ad_account_info_complete, be_req);
    return;

fail:
    be_req_terminate(be_req, DP_ERR_FATAL, ret, NULL);
}

static void
ad_account_info_complete(struct tevent_req *req)
{
    struct be_req *be_req;
    errno_t ret;
    int dp_error;
    const char *error_text = "Internal error";
    const char *req_error_text;

    be_req = tevent_req_callback_data(req, struct be_req);

    ret = ad_handle_acct_info_recv(req, &dp_error, &req_error_text);
    talloc_zfree(req);
    if (dp_error == DP_ERR_OK) {
        if (ret == EOK) {
            error_text = NULL;
        } else {
            DEBUG(SSSDBG_FATAL_FAILURE,
                  ("Bug: dp_error is OK on failed request"));
            dp_error = DP_ERR_FATAL;
            error_text = req_error_text;
        }
    } else if (dp_error == DP_ERR_OFFLINE) {
        error_text = "Offline";
    } else if (dp_error == DP_ERR_FATAL && ret == ENOMEM) {
        error_text = "Out of memory";
    } else {
        error_text = req_error_text;
    }

    return be_req_terminate(be_req, dp_error, ret, error_text);
}

void
ad_check_online(struct be_req *be_req)
{
    struct ad_id_ctx *ad_ctx;
    struct be_ctx *be_ctx = be_req_get_be_ctx(be_req);

    ad_ctx = talloc_get_type(be_ctx->bet_info[BET_ID].pvt_bet_data,
                             struct ad_id_ctx);

    return sdap_do_online_check(be_req, ad_ctx->sdap_id_ctx);
}

struct ad_enumeration_state {
    struct ldap_enum_ctx *ectx;
    struct sdap_id_op *sdap_op;
    struct tevent_context *ev;

    struct sdap_domain *sdom;
};

static void ad_enumeration_conn_done(struct tevent_req *subreq);
static void ad_enumeration_master_done(struct tevent_req *subreq);
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
        ret = EFAULT;
        goto fail;
    }

    state->ectx = ectx;
    state->ev = ev;
    state->sdom = ectx->sdom;

    state->sdap_op = sdap_id_op_create(state, ectx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_create failed.\n"));
        ret = ENOMEM;
        goto fail;
    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret)));
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
                  ("Backend is marked offline, retry later!\n"));
            tevent_req_done(req);
        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  ("Domain enumeration failed to connect to " \
                   "LDAP server: (%d)[%s]\n", ret, strerror(ret)));
            tevent_req_error(req, ret);
        }
        return;
    }

    subreq = ad_master_domain_send(state, state->ev,
                                   state->ectx->conn,
                                   state->sdap_op,
                                   state->sdom->dom->name);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ad_master_domain_send failed.\n"));
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
                                &flat_name, &master_sid, &forest);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot retrieve master domain info\n"));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_master_domain_add_info(state->sdom->dom,
                                       flat_name, master_sid, forest);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("Cannot save master domain info\n"));
        tevent_req_error(req, ret);
        return;
    }

    subreq = sdap_dom_enum_send(state, state->ev, state->ectx->ctx,
                                state->sdom, state->ectx->conn);
    if (subreq == NULL) {
        /* The ptask API will reschedule the enumeration on its own on
         * failure */
        DEBUG(SSSDBG_OP_FAILURE,
              ("Failed to schedule enumeration, retrying later!\n"));
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ad_enumeration_done, req);
}

static void
ad_enumeration_done(struct tevent_req *subreq)
{
    errno_t ret;
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ad_enumeration_state *state = tevent_req_data(req,
                                                struct ad_enumeration_state);

    ret = sdap_dom_enum_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              ("Could not enumerate domain %s\n", state->sdom->dom->name));
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t
ad_enumeration_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}
