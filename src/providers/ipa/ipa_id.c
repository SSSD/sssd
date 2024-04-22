/*
    SSSD

    IPA Identity Backend Module

    Authors:
        Jan Zeleny <jzeleny@redhat.com>

    Copyright (C) 2011 Red Hat

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
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ipa/ipa_id.h"

static bool is_object_overridable(struct dp_id_data *ar)
{
    bool ret = false;

    switch (ar->entry_type & BE_REQ_TYPE_MASK) {
    case BE_REQ_USER:
    case BE_REQ_GROUP:
    case BE_REQ_INITGROUPS:
    case BE_REQ_BY_SECID:
    case BE_REQ_USER_AND_GROUP:
    case BE_REQ_BY_UUID:
    case BE_REQ_BY_CERT:
        ret = true;
        break;
    default:
        break;
    }

    return ret;
}

struct ipa_resolve_user_list_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct ldb_message_element *users;
    const char *domain_name;
    struct sss_domain_info *domain;
    struct sss_domain_info *user_domain;
    size_t user_idx;

    int dp_error;
};

static errno_t ipa_resolve_user_list_get_user_step(struct tevent_req *req);
static void ipa_resolve_user_list_get_user_done(struct tevent_req *subreq);

struct tevent_req *
ipa_resolve_user_list_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                           struct ipa_id_ctx *ipa_ctx,
                           const char *domain_name,
                           struct ldb_message_element *users)
{
    int ret;
    struct tevent_req *req;
    struct ipa_resolve_user_list_state *state;

    req = tevent_req_create(memctx, &state,
                            struct ipa_resolve_user_list_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->domain_name = domain_name;
    state->domain = find_domain_by_name(state->ipa_ctx->sdap_id_ctx->be->domain,
                                        state->domain_name, true);
    state->users = users;
    state->user_idx = 0;
    state->dp_error = DP_ERR_FATAL;

    ret = ipa_resolve_user_list_get_user_step(req);
    if (ret == EAGAIN) {
        return req;
    } else if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_resolve_user_list_get_user_step failed.\n");
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, ev);
    return req;
}

static errno_t ipa_resolve_user_list_get_user_step(struct tevent_req *req)
{
    int ret;
    struct tevent_req *subreq;
    struct dp_id_data *ar;
    struct ipa_resolve_user_list_state *state = tevent_req_data(req,
                                            struct ipa_resolve_user_list_state);

    if (state->user_idx >= state->users->num_values) {
        return EOK;
    }

    ret = get_dp_id_data_for_user_name(state,
                            (char *) state->users->values[state->user_idx].data,
                            state->domain_name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_user_name failed.\n");
        return ret;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Trying to resolve user [%s].\n", ar->filter_value);

    state->user_domain = find_domain_by_object_name_ex(
                                        state->ipa_ctx->sdap_id_ctx->be->domain,
                                        ar->filter_value, true,
                                        SSS_GND_DESCEND);
    /* Use provided domain as fallback because no known domain was found in the
     * user name. */
    if (state->user_domain == NULL) {
        state->user_domain = state->domain;
    }
    ar->domain = state->user_domain->name;

    if (state->user_domain != state->ipa_ctx->sdap_id_ctx->be->domain) {
        subreq = ipa_subdomain_account_send(state, state->ev, state->ipa_ctx,
                                            ar);
    } else {
        subreq = ipa_id_get_account_info_send(state, state->ev, state->ipa_ctx,
                                              ar);
    }
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_handle_acct_req_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(subreq, ipa_resolve_user_list_get_user_done, req);

    return EAGAIN;
}

static void ipa_resolve_user_list_get_user_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_resolve_user_list_state *state = tevent_req_data(req,
                                            struct ipa_resolve_user_list_state);
    int ret;

    if (state->user_domain != state->ipa_ctx->sdap_id_ctx->be->domain) {
        ret = ipa_subdomain_account_recv(subreq, &state->dp_error);
    } else {
        ret = ipa_id_get_account_info_recv(subreq, &state->dp_error);
    }
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_handle_acct request failed: %d\n", ret);
        goto done;
    }

    state->user_idx++;

    ret = ipa_resolve_user_list_get_user_step(req);
    if (ret == EAGAIN) {
        return;
    }
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "ipa_resolve_user_list_get_user_step failed.\n");
    }

done:
    if (ret == EOK) {
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
    } else {
        if (state->dp_error == DP_ERR_OK) {
            state->dp_error = DP_ERR_FATAL;
        }
        tevent_req_error(req, ret);
    }
    return;
}

int ipa_resolve_user_list_recv(struct tevent_req *req, int *dp_error)
{
    struct ipa_resolve_user_list_state *state = tevent_req_data(req,
                                            struct ipa_resolve_user_list_state);

    if (dp_error) {
        *dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct ipa_initgr_get_overrides_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sss_domain_info *user_dom;
    const char *realm;

    struct ldb_message **groups;
    size_t group_count;
    const char *groups_id_attr;
    size_t group_idx;
    struct dp_id_data *ar;

    int dp_error;
};

static int ipa_initgr_get_overrides_step(struct tevent_req *req);

struct tevent_req *
ipa_initgr_get_overrides_send(TALLOC_CTX *memctx,
                             struct tevent_context *ev,
                             struct ipa_id_ctx *ipa_ctx,
                             struct sss_domain_info *user_dom,
                             size_t groups_count,
                             struct ldb_message **groups,
                             const char *groups_id_attr)
{
    int ret;
    struct tevent_req *req;
    struct ipa_initgr_get_overrides_state *state;

    req = tevent_req_create(memctx, &state,
                            struct ipa_initgr_get_overrides_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }
    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->user_dom = user_dom;
    state->groups = groups;
    state->group_count = groups_count;
    state->group_idx = 0;
    state->ar = NULL;
    state->realm = dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                     IPA_KRB5_REALM);
    if (state->realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
        ret = EINVAL;
        goto done;
    }
    state->groups_id_attr = talloc_strdup(state, groups_id_attr);
    if (state->groups_id_attr == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ipa_initgr_get_overrides_step(req);
done:
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, ev);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, ev);
    }

    return req;
}

static void ipa_initgr_get_overrides_override_done(struct tevent_req *subreq);

static int ipa_initgr_get_overrides_step(struct tevent_req *req)
{
    int ret;
    struct tevent_req *subreq;
    const char *ipa_uuid;
    const char *dn;
    struct ipa_initgr_get_overrides_state *state = tevent_req_data(req,
                                        struct ipa_initgr_get_overrides_state);

    for (; state->group_idx < state->group_count; state->group_idx++) {
        dn = ldb_dn_get_linearized(state->groups[state->group_idx]->dn);

        DEBUG(SSSDBG_TRACE_LIBS, "Processing group %s (%zu/%zu)\n",
              dn, state->group_idx, state->group_count);

        ipa_uuid = ldb_msg_find_attr_as_string(state->groups[state->group_idx],
                                               state->groups_id_attr, NULL);
        if (ipa_uuid == NULL) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "The group %s has no UUID attribute %s, error!\n",
                  dn, state->groups_id_attr);
            continue;
        }

        talloc_free(state->ar); /* Avoid spiking memory with many groups */

        if (strcmp(state->groups_id_attr, SYSDB_UUID) == 0) {
            ret = get_dp_id_data_for_uuid(state, ipa_uuid,
                                          state->user_dom->name, &state->ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
                return ret;
            }
        } else if (strcmp(state->groups_id_attr, SYSDB_SID_STR) == 0) {
            ret = get_dp_id_data_for_sid(state, ipa_uuid,
                                         state->user_dom->name, &state->ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
                return ret;
            }
        } else {
            DEBUG(SSSDBG_CRIT_FAILURE, "Unsupported groups ID type [%s].\n",
                  state->groups_id_attr);
            return EINVAL;
        }

        DEBUG(SSSDBG_TRACE_LIBS, "Fetching group %s: %s\n", dn, ipa_uuid);

        subreq = ipa_get_trusted_override_send(state, state->ev,
                                          state->ipa_ctx->sdap_id_ctx,
                                          state->ipa_ctx->ipa_options,
                                          state->realm,
                                          state->ipa_ctx->view_name,
                                          state->ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
            return ENOMEM;
        }
        tevent_req_set_callback(subreq,
                                ipa_initgr_get_overrides_override_done, req);
        return EAGAIN;
    }

    return EOK;
}

static void ipa_initgr_get_overrides_override_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_initgr_get_overrides_state *state = tevent_req_data(req,
                                        struct ipa_initgr_get_overrides_state);
    int ret;
    struct sysdb_attrs *override_attrs = NULL;

    ret = ipa_get_trusted_override_recv(subreq, &state->dp_error, state,
                                   &override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        tevent_req_error(req, ret);
        return;
    }

    if (is_default_view(state->ipa_ctx->view_name)) {
        ret = sysdb_apply_default_override(state->user_dom, override_attrs,
                                       state->groups[state->group_idx]->dn);
    } else {
        ret = sysdb_store_override(state->user_dom,
                                   state->ipa_ctx->view_name,
                                   SYSDB_MEMBER_GROUP,
                                   override_attrs,
                                   state->groups[state->group_idx]->dn);
    }
    talloc_free(override_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_override failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    state->group_idx++;

    ret = ipa_initgr_get_overrides_step(req);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

int ipa_initgr_get_overrides_recv(struct tevent_req *req, int *dp_error)
{
    struct ipa_initgr_get_overrides_state *state = tevent_req_data(req,
                                        struct ipa_initgr_get_overrides_state);

    if (dp_error) {
        *dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

/* Given a user name, retrieve an array of group UUIDs of groups that have
 * no overrideDN attribute but do have an UUID attribute.
 */
static errno_t ipa_id_get_group_uuids(TALLOC_CTX *mem_ctx,
                                      struct sysdb_ctx *sysdb,
                                      size_t *_msgs_count,
                                      struct ldb_message ***_msgs)
{
    const char *filter;
    TALLOC_CTX *tmp_ctx;
    char **uuid_list = NULL;
    errno_t ret;
    struct ldb_dn *base_dn;
    const char *attrs[] = { SYSDB_UUID, NULL };
    size_t msgs_count;
    struct ldb_message **msgs;

    tmp_ctx = talloc_new(mem_ctx);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    filter = talloc_asprintf(tmp_ctx,
                             "(&(%s=%s)(!(%s=*))(%s=*))",
                             SYSDB_OBJECTCATEGORY,
                             SYSDB_GROUP_CLASS, SYSDB_OVERRIDE_DN,
                             SYSDB_UUID);
    if (filter == NULL) {
        ret = ENOMEM;
        goto done;
    }

    base_dn = sysdb_base_dn(sysdb, tmp_ctx);
    if (base_dn == NULL) {
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_entry(tmp_ctx, sysdb, base_dn,
                             LDB_SCOPE_SUBTREE, filter, attrs,
                             &msgs_count, &msgs);
    if (ret == ENOENT) {
        DEBUG(SSSDBG_TRACE_FUNC,
              "No groups without %s in sysdb\n", SYSDB_OVERRIDE_DN);
        ret = EOK;
        goto done;
    } else if (ret != EOK) {
        goto done;
    }

    uuid_list = talloc_zero_array(tmp_ctx, char *, msgs_count);
    if (uuid_list == NULL) {
        goto done;
    }

    *_msgs_count = msgs_count;
    *_msgs = talloc_steal(mem_ctx, msgs);
    ret = EOK;
done:
    talloc_free(tmp_ctx);
    return ret;
}

struct ipa_id_get_account_info_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ipa_ctx;
    struct sdap_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;
    struct dp_id_data *ar;
    struct dp_id_data *orig_ar;
    const char *realm;

    struct sysdb_attrs *override_attrs;
    struct ldb_message *obj_msg;
    struct ldb_message_element *ghosts;

    struct ldb_message **user_groups;
    size_t group_cnt;
    size_t group_idx;

    struct ldb_result *res;
    size_t res_index;
    int dp_error;
};

static void ipa_id_get_account_info_connected(struct tevent_req *subreq);
static void ipa_id_get_account_info_got_override(struct tevent_req *subreq);
static errno_t ipa_id_get_account_info_get_original_step(struct tevent_req *req,
                                                        struct dp_id_data *ar);
static void ipa_id_get_account_info_orig_done(struct tevent_req *subreq);
static void ipa_id_get_account_info_done(struct tevent_req *subreq);
static void ipa_id_get_user_list_done(struct tevent_req *subreq);

struct tevent_req *
ipa_id_get_account_info_send(TALLOC_CTX *memctx, struct tevent_context *ev,
                             struct ipa_id_ctx *ipa_ctx,
                             struct dp_id_data *ar)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct ipa_id_get_account_info_state *state;

    req = tevent_req_create(memctx, &state,
                            struct ipa_id_get_account_info_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->ipa_ctx = ipa_ctx;
    state->ctx = ipa_ctx->sdap_id_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, state->ctx->conn->conn_cache);
    if (state->op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed.\n");
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
    state->realm = dp_opt_get_string(state->ipa_ctx->ipa_options->basic,
                                     IPA_KRB5_REALM);
    if (state->realm == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "No Kerberos realm for IPA?\n");
        ret = EINVAL;
        goto fail;
    }

    /* We can skip the override lookup and go directly to the original object
     * if
     * - the lookup is by SID
     * - there is no view set of it is the default view
     * - if the EXTRA_INPUT_MAYBE_WITH_VIEW flag is not set
     */
    if (is_default_view(state->ipa_ctx->view_name)
            || state->ar->filter_type == BE_FILTER_SECID
            || state->ar->extra_value == NULL
            || strcmp(state->ar->extra_value,
                      EXTRA_INPUT_MAYBE_WITH_VIEW) != 0
            || ! is_object_overridable(state->ar)) {
        ret = ipa_id_get_account_info_get_original_step(req, ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_subdomain_account_get_original_step failed.\n");
            goto fail;
        }
    } else {
        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed.\n");
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_id_get_account_info_connected, req);
    }

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_id_get_account_info_connected(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect request failed.\n");
        goto fail;
    }

    subreq = ipa_get_trusted_override_send(state, state->ev, state->ctx,
                                           state->ipa_ctx->ipa_options, state->realm,
                                           state->ipa_ctx->view_name, state->ar);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_id_get_account_info_got_override, req);

    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

static void ipa_id_get_account_info_got_override(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    const char *anchor = NULL;
    char *anchor_domain;
    char *ipa_uuid;

    ret = ipa_get_trusted_override_recv(subreq, &dp_error, state,
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
            tevent_req_set_callback(subreq, ipa_id_get_account_info_connected,
                                    req);
            return;
        }

        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
    }

    if (state->override_attrs != NULL) {
        ret = sysdb_attrs_get_string(state->override_attrs,
                                     SYSDB_OVERRIDE_ANCHOR_UUID,
                                     &anchor);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_get_string failed.\n");
            goto fail;
        }

        ret = split_ipa_anchor(state, anchor, &anchor_domain, &ipa_uuid);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Unsupported override anchor [%s].\n", anchor);
            ret = EINVAL;
            goto fail;
        }

        if (strcmp(state->ar->domain, anchor_domain) == 0) {

            state->orig_ar = state->ar;

            ret = get_dp_id_data_for_uuid(state, ipa_uuid,
                                           state->ar->domain,
                                           &state->ar);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_uuid failed.\n");
                goto fail;
            }

            if ((state->orig_ar->entry_type & BE_REQ_TYPE_MASK)
                                                         == BE_REQ_INITGROUPS) {
                DEBUG(SSSDBG_TRACE_ALL,
                      "Switching back to BE_REQ_INITGROUPS.\n");
                state->ar->entry_type = BE_REQ_INITGROUPS;
                state->ar->filter_type = BE_FILTER_UUID;
            }

        } else {
            DEBUG(SSSDBG_MINOR_FAILURE,
                  "Anchor from a different domain [%s], expected [%s]. " \
                  "This is currently not supported, continue lookup in " \
                  "local IPA domain.\n",
                  anchor_domain, state->ar->domain);
        }
    }

    ret = ipa_id_get_account_info_get_original_step(req, state->ar);
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

static errno_t ipa_id_get_account_info_get_original_step(struct tevent_req *req,
                                                         struct dp_id_data *ar)
{
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    struct tevent_req *subreq;

#ifdef BUILD_SUBID
    if ((ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_SUBID_RANGES) {
        if (!state->ctx->opts->sdom->subid_ranges_search_bases ||
            !state->ctx->opts->sdom->subid_ranges_search_bases[0] ||
            !state->ctx->opts->sdom->subid_ranges_search_bases[0]->basedn) {
            DEBUG(SSSDBG_OP_FAILURE, "subid_ranges_search_bases isn't set\n");
            return EINVAL;
        }
        ar->extra_value = talloc_asprintf(ar,
            "%s=%s,"SYSDB_USERS_CONTAINER",%s",
            state->ctx->opts->user_map[SDAP_AT_USER_NAME].name,
            ar->filter_value,
            state->ctx->opts->sdom->user_search_bases[0]->basedn);
    }
#endif

    subreq = sdap_handle_acct_req_send(state, state->ctx->be, ar,
                                       state->ipa_ctx->sdap_id_ctx,
                                       state->ipa_ctx->sdap_id_ctx->opts->sdom,
                                       state->ipa_ctx->sdap_id_ctx->conn, true);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_handle_acct_req_send failed.\n");
        return ENOMEM;
    }
    tevent_req_set_callback(subreq, ipa_id_get_account_info_orig_done, req);

    return EOK;
}

static int ipa_id_get_account_info_post_proc_step(struct tevent_req *req);
static void ipa_id_get_user_groups_done(struct tevent_req *subreq);

static void ipa_id_get_account_info_orig_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_UIDNUM,
                            SYSDB_SID_STR,
                            SYSDB_OBJECTCATEGORY,
                            SYSDB_UUID,
                            SYSDB_GHOST,
                            SYSDB_HOMEDIR,
                            NULL };

    ret = sdap_handle_acct_req_recv(subreq, &dp_error, NULL, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_handle_acct request failed: %d\n", ret);
        goto fail;
    }

    if (! is_object_overridable(state->ar)) {
        DEBUG(SSSDBG_FUNC_DATA, "Object not overridable, ending request\n");
        state->dp_error = DP_ERR_OK;
        tevent_req_done(req);
        return;
    }

    /* Lookups by certificate can return muliple results and need special
     * handling because get_object_from_cache() expects a unique match */
    state->res = NULL;
    state->res_index = 0;
    if (state->ar->filter_type == BE_FILTER_CERT) {
        ret = sysdb_search_object_by_cert(state, state->domain,
                                          state->ar->filter_value, attrs,
                                          &(state->res));
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to make request to our cache: [%d]: [%s]\n",
                  ret, sss_strerror(ret));
            goto fail;
        }
        if (state->res->count == 0) {
            DEBUG(SSSDBG_OP_FAILURE, "Object not found in our cache.\n");
            ret = ENOENT;
            goto fail;
        }

        state->obj_msg = state->res->msgs[0];
        if (state->res->count == 1) {
            /* Just process the unique result, no need to iterate */
            state->res = NULL;
        }
    } else {
        ret = get_object_from_cache(state, state->domain, state->ar,
                                    &state->obj_msg);
        if (ret == ENOENT) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Object not found, ending request\n");
            state->dp_error = DP_ERR_OK;
            tevent_req_done(req);
            return;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_object_from_cache failed.\n");
            goto fail;
        }
    }

    ret = ipa_id_get_account_info_post_proc_step(req);
    if (ret == EAGAIN) {
        return;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_id_get_account_info_post_proc_step failed.\n");
        goto fail;
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

static int ipa_id_get_account_info_post_proc_step(struct tevent_req *req)
{
    int ret;
    const char *uuid;
    const char *class;
    enum sysdb_member_type type;
    struct tevent_req *subreq;
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);

    class = ldb_msg_find_attr_as_string(state->obj_msg, SYSDB_OBJECTCATEGORY,
                                        NULL);
    if (class == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find an objectclass.\n");
        ret = EINVAL;
        goto done;
    }


    if (!is_default_view(state->ipa_ctx->view_name)) {

        if ((state->ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_GROUP
                || ((state->ar->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_BY_UUID
                        && strcmp(class, SYSDB_GROUP_CLASS) == 0)) {
            /* check for ghost members because ghost members are not allowed
             * if a view other than the default view is applied.*/
            state->ghosts = ldb_msg_find_element(state->obj_msg, SYSDB_GHOST);
        } else if ((state->ar->entry_type & BE_REQ_TYPE_MASK) == \
                        BE_REQ_INITGROUPS) {
            /* Get UUID list of groups that have no overrideDN set. */
            ret = ipa_id_get_group_uuids(state, state->sysdb,
                                         &state->group_cnt,
                                         &state->user_groups);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "Cannot get UUID list: %d\n", ret);
                goto done;
            }
        }
    }


    if (state->override_attrs == NULL) {
        uuid = ldb_msg_find_attr_as_string(state->obj_msg, SYSDB_UUID, NULL);
        if (uuid == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find a UUID.\n");
            ret = EINVAL;
            goto done;
        }

        ret = get_dp_id_data_for_uuid(state, uuid, state->domain->name,
                                       &state->ar);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "get_dp_id_data_for_sid failed.\n");
            goto done;
        }

        subreq = ipa_get_trusted_override_send(state, state->ev,
                                               state->ipa_ctx->sdap_id_ctx,
                                               state->ipa_ctx->ipa_options,
                                               state->realm,
                                               state->ipa_ctx->view_name,
                                               state->ar);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_get_trusted_override_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_id_get_account_info_done, req);
        ret = EAGAIN;
        goto done;
    } else {
        if (strcmp(class, SYSDB_USER_CLASS) == 0) {
            type = SYSDB_MEMBER_USER;
        } else {
            type = SYSDB_MEMBER_GROUP;
        }

        ret = sysdb_store_override(state->domain, state->ipa_ctx->view_name,
                                   type,
                                   state->override_attrs, state->obj_msg->dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_override failed.\n");
            goto done;
        }
    }

    if (state->ghosts != NULL) {
        /* Resolve ghost members */
        subreq = ipa_resolve_user_list_send(state, state->ev,
                                            state->ipa_ctx,
                                            state->domain->name,
                                            state->ghosts);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_id_get_user_list_done, req);
        ret = EAGAIN;
        goto done;
    }

    if (state->user_groups != NULL) {
        subreq = ipa_initgr_get_overrides_send(state, state->ev, state->ipa_ctx,
                                              state->domain, state->group_cnt,
                                              state->user_groups,
                                              SYSDB_UUID);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list_send failed.\n");
            ret = ENOMEM;
            goto done;
        }
        tevent_req_set_callback(subreq, ipa_id_get_user_groups_done, req);
        ret = EAGAIN;
        goto done;
    }

    ret = EOK;

done:
    if (ret == EOK && state->res != NULL
            && ++state->res_index < state->res->count) {
        state->obj_msg = state->res->msgs[state->res_index];
        ret = ipa_id_get_account_info_post_proc_step(req);
    }

    return ret;
}

static void ipa_id_get_account_info_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    const char *class;
    enum sysdb_member_type type;

    ret = ipa_get_trusted_override_recv(subreq, &dp_error, state,
                                        &state->override_attrs);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA override lookup failed: %d\n", ret);
        goto fail;
    }

    class = ldb_msg_find_attr_as_string(state->obj_msg, SYSDB_OBJECTCATEGORY,
                                        NULL);
    if (class == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Cannot find an objectclass.\n");
        ret = EINVAL;
        goto fail;
    }

    if (strcmp(class, SYSDB_USER_CLASS) == 0) {
        type = SYSDB_MEMBER_USER;
    } else {
        type = SYSDB_MEMBER_GROUP;
    }

    ret = sysdb_store_override(state->domain, state->ipa_ctx->view_name,
                               type,
                               state->override_attrs, state->obj_msg->dn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_override failed.\n");
        goto fail;
    }

    if (state->ghosts != NULL) {
        /* Resolve ghost members */
        subreq = ipa_resolve_user_list_send(state, state->ev,
                                            state->ipa_ctx,
                                            state->domain->name,
                                            state->ghosts);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list_send failed.\n");
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_id_get_user_list_done, req);
        return;
    }

    if (state->user_groups != NULL) {
        subreq = ipa_initgr_get_overrides_send(state, state->ev, state->ipa_ctx,
                                               state->domain, state->group_cnt,
                                               state->user_groups,
                                               SYSDB_UUID);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_resolve_user_list_send failed.\n");
            ret = ENOMEM;
            goto fail;
        }
        tevent_req_set_callback(subreq, ipa_id_get_user_groups_done, req);
        return;
    }

    if (state->res != NULL && ++state->res_index < state->res->count) {
        state->obj_msg = state->res->msgs[state->res_index];
        ret = ipa_id_get_account_info_post_proc_step(req);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_id_get_account_info_post_proc_step failed.\n");
            goto fail;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

static void ipa_id_get_user_list_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_resolve_user_list_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA resolve user list %d\n", ret);
        goto fail;
    }

    if (state->res != NULL && ++state->res_index < state->res->count) {
        state->obj_msg = state->res->msgs[state->res_index];
        ret = ipa_id_get_account_info_post_proc_step(req);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_id_get_account_info_post_proc_step failed.\n");
            goto fail;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

static void ipa_id_get_user_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                struct tevent_req);
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_initgr_get_overrides_recv(subreq, &dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "IPA resolve user groups %d\n", ret);
        goto fail;
    }

    if (state->res != NULL && ++state->res_index < state->res->count) {
        state->obj_msg = state->res->msgs[state->res_index];
        ret = ipa_id_get_account_info_post_proc_step(req);
        if (ret == EAGAIN) {
            return;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "ipa_id_get_account_info_post_proc_step failed.\n");
            goto fail;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;

fail:
    state->dp_error = dp_error;
    tevent_req_error(req, ret);
    return;
}

int ipa_id_get_account_info_recv(struct tevent_req *req, int *dp_error)
{
    struct ipa_id_get_account_info_state *state = tevent_req_data(req,
                                          struct ipa_id_get_account_info_state);

    if (dp_error) {
        *dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

/* Request for netgroups
 * - first start here and then go to ipa_netgroups.c
 */
struct ipa_id_get_netgroup_state {
    struct tevent_context *ev;
    struct ipa_id_ctx *ctx;
    struct sdap_id_op *op;
    struct sysdb_ctx *sysdb;
    struct sss_domain_info *domain;

    const char *name;
    int timeout;

    char *filter;
    const char **attrs;

    size_t count;
    struct sysdb_attrs **netgroups;

    int dp_error;
};

static void ipa_id_get_netgroup_connected(struct tevent_req *subreq);
static void ipa_id_get_netgroup_done(struct tevent_req *subreq);

static struct tevent_req *ipa_id_get_netgroup_send(TALLOC_CTX *memctx,
                                                   struct tevent_context *ev,
                                                   struct ipa_id_ctx *ipa_ctx,
                                                   const char *name)
{
    struct tevent_req *req;
    struct ipa_id_get_netgroup_state *state;
    struct tevent_req *subreq;
    struct sdap_id_ctx *ctx;
    char *clean_name;
    int ret;

    ctx = ipa_ctx->sdap_id_ctx;

    req = tevent_req_create(memctx, &state, struct ipa_id_get_netgroup_state);
    if (!req) return NULL;

    state->ev = ev;
    state->ctx = ipa_ctx;
    state->dp_error = DP_ERR_FATAL;

    state->op = sdap_id_op_create(state, ctx->conn->conn_cache);
    if (!state->op) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto fail;
    }

    state->sysdb = ctx->be->domain->sysdb;
    state->domain = ctx->be->domain;
    state->name = name;
    state->timeout = dp_opt_get_int(ctx->opts->basic, SDAP_SEARCH_TIMEOUT);

    ret = sss_filter_sanitize(state, name, &clean_name);
    if (ret != EOK) {
        goto fail;
    }

    state->filter = talloc_asprintf(state, "(&(%s=%s)(objectclass=%s))",
                            ctx->opts->netgroup_map[IPA_AT_NETGROUP_NAME].name,
                            clean_name,
                            ctx->opts->netgroup_map[IPA_OC_NETGROUP].name);
    if (!state->filter) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to build filter\n");
        ret = ENOMEM;
        goto fail;
    }
    talloc_zfree(clean_name);

    ret = build_attrs_from_map(state, ctx->opts->netgroup_map,
                               IPA_OPTS_NETGROUP, NULL,
                               &state->attrs, NULL);
    if (ret != EOK) goto fail;

    subreq = sdap_id_op_connect_send(state->op, state, &ret);
    if (!subreq) {
        goto fail;
    }
    tevent_req_set_callback(subreq, ipa_id_get_netgroup_connected, req);

    return req;

fail:
    tevent_req_error(req, ret);
    tevent_req_post(req, ev);
    return req;
}

static void ipa_id_get_netgroup_connected(struct tevent_req *subreq)
{
    struct tevent_req *req =
                    tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);
    int dp_error = DP_ERR_FATAL;
    int ret;
    struct sdap_id_ctx *sdap_ctx = state->ctx->sdap_id_ctx;

    ret = sdap_id_op_connect_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    if (ret != EOK) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    subreq = ipa_get_netgroups_send(state, state->ev, state->sysdb,
                                    state->domain, sdap_ctx->opts,
                                    state->ctx->ipa_options,
                                    sdap_id_op_handle(state->op),
                                    state->attrs, state->filter,
                                    state->timeout);
    if (!subreq) {
        tevent_req_error(req, ENOMEM);
        return;
    }
    tevent_req_set_callback(subreq, ipa_id_get_netgroup_done, req);

    return;
}

static void ipa_id_get_netgroup_done(struct tevent_req *subreq)
{
    struct tevent_req *req =
                    tevent_req_callback_data(subreq, struct tevent_req);
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);
    int dp_error = DP_ERR_FATAL;
    int ret;

    ret = ipa_get_netgroups_recv(subreq, state,
                                 &state->count, &state->netgroups);
    talloc_zfree(subreq);
    ret = sdap_id_op_done(state->op, ret, &dp_error);

    if (dp_error == DP_ERR_OK && ret != EOK) {
        /* retry */
        subreq = sdap_id_op_connect_send(state->op, state, &ret);
        if (!subreq) {
            tevent_req_error(req, ret);
            return;
        }
        tevent_req_set_callback(subreq, ipa_id_get_netgroup_connected, req);
        return;
    }

    if (ret && ret != ENOENT) {
        state->dp_error = dp_error;
        tevent_req_error(req, ret);
        return;
    }

    if (ret == EOK && state->count > 1) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Found more than one netgroup with the name [%s].\n",
                  state->name);
        tevent_req_error(req, EINVAL);
        return;
    }

    if (ret == ENOENT) {
        ret = sysdb_delete_netgroup(state->domain, state->name);
        if (ret != EOK && ret != ENOENT) {
            tevent_req_error(req, ret);
            return;
        }
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

static int ipa_id_get_netgroup_recv(struct tevent_req *req, int *dp_error)
{
    struct ipa_id_get_netgroup_state *state =
                    tevent_req_data(req, struct ipa_id_get_netgroup_state);

    if (dp_error) {
        *dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

enum ipa_account_info_type {
    IPA_ACCOUNT_INFO_SUBDOMAIN,
    IPA_ACCOUNT_INFO_NETGROUP,
    IPA_ACCOUNT_INFO_OTHER
};

static enum ipa_account_info_type
ipa_decide_account_info_type(struct dp_id_data *data, struct be_ctx *be_ctx)
{
    if (strcasecmp(data->domain, be_ctx->domain->name) != 0) {
        return IPA_ACCOUNT_INFO_SUBDOMAIN;
    } else if ((data->entry_type & BE_REQ_TYPE_MASK) == BE_REQ_NETGROUP) {
        return IPA_ACCOUNT_INFO_NETGROUP;
    }

    return IPA_ACCOUNT_INFO_OTHER;
}

struct ipa_account_info_state {
    enum ipa_account_info_type type;

    const char *err_msg;
    int dp_error;
};

static void ipa_account_info_done(struct tevent_req *subreq);

struct tevent_req *
ipa_account_info_send(TALLOC_CTX *mem_ctx,
                      struct be_ctx *be_ctx,
                      struct ipa_id_ctx *id_ctx,
                      struct dp_id_data *data)
{
    struct ipa_account_info_state *state = NULL;
    struct tevent_req *req = NULL;
    struct tevent_req *subreq = NULL;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_account_info_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    state->type = ipa_decide_account_info_type(data, be_ctx);

    switch (state->type) {
    case IPA_ACCOUNT_INFO_SUBDOMAIN:
        /* Subdomain lookups are handled differently on server and client. */
        subreq = ipa_subdomain_account_send(state, be_ctx->ev, id_ctx, data);
        break;
    case IPA_ACCOUNT_INFO_NETGROUP:
        if (data->filter_type != BE_FILTER_NAME) {
            ret = EINVAL;
            goto immediately;
        }

        subreq = ipa_id_get_netgroup_send(state, be_ctx->ev, id_ctx,
                                          data->filter_value);
        break;
    case IPA_ACCOUNT_INFO_OTHER:
        subreq = ipa_id_get_account_info_send(state, be_ctx->ev, id_ctx, data);
        break;
    }

    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, ipa_account_info_done, req);
    return req;

immediately:
    tevent_req_error(req, ret);
    tevent_req_post(req, be_ctx->ev);
    return req;
}

static void ipa_account_info_done(struct tevent_req *subreq)
{
    struct ipa_account_info_state *state = NULL;
    struct tevent_req *req = NULL;
    errno_t ret;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_account_info_state);

    switch (state->type) {
    case IPA_ACCOUNT_INFO_SUBDOMAIN:
        ret = ipa_subdomain_account_recv(subreq, &state->dp_error);
        break;
    case IPA_ACCOUNT_INFO_NETGROUP:
        ret = ipa_id_get_netgroup_recv(subreq, &state->dp_error);
        break;
    case IPA_ACCOUNT_INFO_OTHER:
        ret = ipa_id_get_account_info_recv(subreq, &state->dp_error);
        break;
    default:
        ret = EINVAL;
        break;
    }
    talloc_zfree(subreq);

    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t ipa_account_info_recv(struct tevent_req *req,
                              int *_dp_error)
{
    struct ipa_account_info_state *state = NULL;

    state = tevent_req_data(req, struct ipa_account_info_state);

    /* Fail the request after collecting the dp_error */
    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    TEVENT_REQ_RETURN_ON_ERROR(req);
    return EOK;
}

struct ipa_account_info_handler_state {
    struct dp_reply_std reply;
};

static void ipa_account_info_handler_done(struct tevent_req *subreq);

struct tevent_req *
ipa_account_info_handler_send(TALLOC_CTX *mem_ctx,
                              struct ipa_id_ctx *id_ctx,
                              struct dp_id_data *data,
                              struct dp_req_params *params)
{
    struct ipa_account_info_handler_state *state;
    struct tevent_req *subreq = NULL;
    struct tevent_req *req;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state,
                            struct ipa_account_info_handler_state);
    if (req == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "tevent_req_create() failed\n");
        return NULL;
    }

    if (sdap_is_enum_request(data)) {
        DEBUG(SSSDBG_TRACE_LIBS, "Skipping enumeration on demand\n");
        ret = EOK;
        goto immediately;
    }

    subreq = ipa_account_info_send(state, params->be_ctx, id_ctx, data);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediately;
    }
    tevent_req_set_callback(subreq, ipa_account_info_handler_done, req);

    return req;

immediately:
    dp_reply_std_set(&state->reply, DP_ERR_DECIDE, ret, NULL);

    /* TODO For backward compatibility we always return EOK to DP now. */
    tevent_req_done(req);
    tevent_req_post(req, params->ev);

    return req;
}

static void ipa_account_info_handler_done(struct tevent_req *subreq)
{
    struct ipa_account_info_handler_state *state;
    struct tevent_req *req;
    int dp_error;
    errno_t ret = ERR_INTERNAL;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ipa_account_info_handler_state);

    ret = ipa_account_info_recv(subreq, &dp_error);
    talloc_zfree(subreq);

    /* TODO For backward compatibility we always return EOK to DP now. */
    dp_reply_std_set(&state->reply, dp_error, ret, NULL);
    tevent_req_done(req);
}

errno_t ipa_account_info_handler_recv(TALLOC_CTX *mem_ctx,
                                      struct tevent_req *req,
                                      struct dp_reply_std *data)
{
    struct ipa_account_info_handler_state *state = NULL;

    state = tevent_req_data(req, struct ipa_account_info_handler_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    *data = state->reply;

    return EOK;
}
