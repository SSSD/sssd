/*
    SSSD

    IPA Identity Backend Module for sub-domains - evaluate external group
    memberships

    Authors:
        Sumit Bose <sbose@redhat.com>

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

#include "util/util.h"
#include "db/sysdb.h"
#include "providers/ldap/ldap_common.h"
#include "providers/ldap/sdap_async.h"
#include "providers/ldap/sdap_ops.h"
#include "providers/ipa/ipa_id.h"
#include "providers/ad/ad_id.h"
#include "providers/ipa/ipa_subdomains.h"

#define IPA_EXT_GROUPS_FILTER "objectClass=ipaexternalgroup"

struct ipa_ext_groups {
    time_t next_update;
    hash_table_t *ext_groups;
};

static errno_t process_ext_groups(TALLOC_CTX *mem_ctx, size_t reply_count,
                                  struct sysdb_attrs **reply,
                                  hash_table_t **_ext_group_hash)
{
    int ret;
    hash_table_t *ext_group_hash = NULL;
    hash_key_t key;
    hash_value_t value;
    hash_table_t *m_hash = NULL;
    hash_key_t m_key;
    hash_value_t m_value;
    size_t g;
    size_t s;
    size_t m;
    TALLOC_CTX *tmp_ctx = NULL;
    const char **ext_sids;
    const char **mof;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sss_hash_create(mem_ctx, reply_count, &ext_group_hash);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
        goto done;
    }

    key.type = HASH_KEY_STRING;
    m_key.type = HASH_KEY_STRING;
    m_value.type = HASH_VALUE_PTR;
    m_value.ptr = NULL;

    for (g = 0; g < reply_count; g++) {
        ret = sysdb_attrs_get_string_array(reply[g], "ipaExternalMember",
                                           tmp_ctx, &ext_sids);
        if (ret == ENOENT) {
            /* no external members, try next external group. */
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_get_string_array failed.\n");
            goto done;
        }

        ret = sysdb_attrs_get_string_array(reply[g], "memberOf",
                                           tmp_ctx, &mof);
        if (ret == ENOENT) {
            /* no IPA groups, try next external group. */
            continue;
        } else if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sysdb_attrs_get_string_array failed.\n");
            goto done;
        }

        for (s = 0; ext_sids[s] != NULL; s++) {
            /* hash_lookup does not modify key.str. */
            key.str = discard_const(ext_sids[s]);
            ret = hash_lookup(ext_group_hash, &key, &value);
            if (ret == HASH_SUCCESS) {
                if (value.type != HASH_VALUE_PTR) {
                    DEBUG(SSSDBG_OP_FAILURE, "Unexpected value type.\n");
                    ret = EINVAL;
                    goto done;
                }

                for (m = 0; mof[m] != NULL; m++) {
                    /* hash_enter does not modify m_key.str. */
                    m_key.str = discard_const(mof[m]);
                    DEBUG(SSSDBG_TRACE_ALL, "Adding group [%s] to SID [%s].\n",
                                             m_key.str, key.str);
                    ret = hash_enter(value.ptr, &m_key, &m_value);
                    if (ret != HASH_SUCCESS) {
                        DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed.\n");
                        goto done;
                    }
                }
            } else if (ret == HASH_ERROR_KEY_NOT_FOUND) {
                ret = sss_hash_create(ext_group_hash, 0, &m_hash);
                if (ret != HASH_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
                    goto done;
                }

                value.type = HASH_VALUE_PTR;
                value.ptr = m_hash;

                DEBUG(SSSDBG_TRACE_ALL,
                      "Adding SID [%s] to external group hash.\n", key.str);
                ret = hash_enter(ext_group_hash, &key, &value);
                if (ret != HASH_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed.\n");
                    goto done;
                }

                for (m = 0; mof[m] != NULL; m++) {
                    /* hash_enter does not modify m_key.str. */
                    m_key.str = discard_const(mof[m]);
                    DEBUG(SSSDBG_TRACE_ALL, "Adding group [%s] to SID [%s].\n",
                                             m_key.str, key.str);
                    ret = hash_enter(m_hash, &m_key, &m_value);
                    if (ret != HASH_SUCCESS) {
                        DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed.\n");
                        goto done;
                    }
                }
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "hash_lookup failed.\n");
                goto done;
            }
        }
    }

    ret = EOK;
done:
    if (ret != EOK) {
        talloc_free(ext_group_hash);
    } else {
        *_ext_group_hash = ext_group_hash;
    }

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t find_ipa_ext_memberships(TALLOC_CTX *mem_ctx,
                                        const char *user_name,
                                        struct sss_domain_info *user_dom,
                                        hash_table_t *ext_group_hash,
                                        struct ldb_dn **_user_dn,
                                        char ***_groups)
{
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *result;
    char **groups = NULL;
    size_t c;
    const char *sid;
    hash_key_t key;
    hash_value_t value;
    hash_entry_t *entry;
    struct hash_iter_context_t *iter;
    hash_table_t *group_hash;
    size_t g_count;
    struct ldb_dn *user_dn = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_initgroups(tmp_ctx, user_dom, user_name, &result);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_initgroups failed.\n");
        goto done;
    }

    if (result->count == 0) {
        DEBUG(SSSDBG_MINOR_FAILURE, "User [%s] not found in cache.\n",
                                     user_name);
        ret = EOK;
        goto done;
    }

    ret = sss_hash_create(tmp_ctx, 0, &group_hash);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
        goto done;
    }

    key.type = HASH_KEY_STRING;

    /* The IPA external domains can have references to group and user SIDs.
     * This means that we not only want to look up the group SIDs but the SID
     * of the user (first element of result) as well. */
    for (c = 0; c < result->count; c++) {
        sid = ldb_msg_find_attr_as_string(result->msgs[c], SYSDB_SID_STR,
                                          NULL);
        if (sid == NULL) {
            DEBUG(SSSDBG_MINOR_FAILURE, "Group [%s] does not have a SID.\n",
                  ldb_dn_get_linearized(result->msgs[c]->dn));
            continue;
        }

        key.str = discard_const(sid);
        ret = hash_lookup(ext_group_hash, &key, &value);
        if (ret == HASH_ERROR_KEY_NOT_FOUND) {
            DEBUG(SSSDBG_TRACE_ALL, "SID [%s] not found in ext group hash.\n",
                                     sid);
        } else if (ret == HASH_SUCCESS) {
            iter = new_hash_iter_context(value.ptr);
            if (iter == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
                ret = EINVAL;
                goto done;
            }

            while ((entry = iter->next(iter)) != NULL) {
                ret = hash_enter(group_hash, &entry->key, &entry->value);
                if (ret != HASH_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to add group [%s].\n",
                                              entry->key.str);
                }
            }

            talloc_free(iter);
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "hash_lookup failed for SID [%s].\n",
                                      sid);
        }
    }

    g_count = hash_count(group_hash);
    if (g_count == 0) {
        DEBUG(SSSDBG_TRACE_FUNC, "No external groupmemberships found.\n");
        ret = EOK;
        goto done;
    }

    groups = talloc_zero_array(mem_ctx, char *, g_count + 1);
    if (groups == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    iter = new_hash_iter_context(group_hash);
    if (iter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
        ret = EINVAL;
        goto done;
    }

    c = 0;
    while ((entry = iter->next(iter)) != NULL) {
        groups[c] = talloc_strdup(groups, entry->key.str);
        if (groups[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        c++;
    }

    user_dn = ldb_dn_copy(mem_ctx, result->msgs[0]->dn);
    if (user_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_copy failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = EOK;
done:
    *_user_dn = user_dn;
    *_groups = groups;

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t add_ad_user_to_cached_groups(struct ldb_dn *user_dn,
                                            struct sss_domain_info *user_dom,
                                            struct sss_domain_info *group_dom,
                                            char **groups,
                                            bool *missing_groups)
{
    size_t c;
    struct sysdb_attrs *user_attrs;
    size_t msgs_count;
    struct ldb_message **msgs;
    TALLOC_CTX *tmp_ctx;
    int ret;

    *missing_groups = false;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    for (c = 0; groups[c] != NULL; c++) {
        if (groups[c][0] == '\0') {
            continue;
        }

        ret = sysdb_search_groups_by_orig_dn(tmp_ctx, group_dom, groups[c],
                                             NULL, &msgs_count, &msgs);
        if (ret != EOK) {
            if (ret == ENOENT) {
                DEBUG(SSSDBG_TRACE_ALL, "Group [%s] not in the cache.\n",
                                         groups[c]);
                *missing_groups = true;
                continue;
            } else {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_entry failed.\n");
                goto done;
            }
        }

/* TODO? Do we have to remove members as well? I think not because the AD
 * query before removes all memberships. */

        ret = sysdb_mod_group_member(group_dom, user_dn, msgs[0]->dn,
                                     LDB_FLAG_MOD_ADD);
        if (ret != EOK && ret != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_mod_group_member failed.\n");
            goto done;
        }

        user_attrs = sysdb_new_attrs(tmp_ctx);
        if (user_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                                     groups[c]);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
            goto done;
        }

        ret = sysdb_set_entry_attr(user_dom->sysdb, user_dn, user_attrs,
                                   LDB_FLAG_MOD_ADD);
        if (ret != EOK && ret != EEXIST) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
            goto done;
        }

        /* mark group as already processed */
        groups[c][0] = '\0';
    }

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

static struct tevent_req *ipa_add_trusted_memberships_send(TALLOC_CTX *mem_ctx,
                                                           struct tevent_context *ev,
                                                           struct sdap_id_ctx *sdap_id_ctx,
                                                           struct ldb_dn *user_dn,
                                                           struct sss_domain_info *user_dom,
                                                           char **groups,
                                                           struct sss_domain_info *group_dom);
static void ipa_add_trusted_memberships_done(struct tevent_req *subreq);

struct get_trusted_membership_state {
    struct tevent_context *ev;
    struct ipa_server_mode_ctx *server_mode;
    struct sdap_id_op *sdap_op;
    struct sdap_id_ctx *sdap_id_ctx;
    struct fo_server *srv;
    char *user_name;
    struct sss_domain_info *user_dom;

    int dp_error;
    const char *domain;
    size_t reply_count;
    struct sysdb_attrs **reply;
};

static void ipa_get_trusted_memberships_connect_done(struct tevent_req *subreq);
static void ipa_get_ext_groups_done(struct tevent_req *subreq);
static errno_t ipa_add_ext_groups_step(struct tevent_req *req);
static errno_t ipa_add_trusted_memberships_recv(struct tevent_req *req,
                                                int *dp_error_out);

struct tevent_req *ipa_get_trusted_memberships_send(TALLOC_CTX *mem_ctx,
                                                    struct tevent_context *ev,
                                                    struct dp_id_data *ar,
                                                    struct ipa_server_mode_ctx *server_mode,
                                                    struct sss_domain_info *user_dom,
                                                    struct sdap_id_ctx *sdap_id_ctx,
                                                    const char *domain)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct get_trusted_membership_state *state;

    req = tevent_req_create(mem_ctx, &state, struct get_trusted_membership_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->user_dom = user_dom;
    state->sdap_id_ctx = sdap_id_ctx;
    state->srv = NULL;
    state->domain = domain;
    state->dp_error = -1;

    if (((ar->entry_type & BE_REQ_TYPE_MASK) != BE_REQ_INITGROUPS
            && (ar->entry_type & BE_REQ_TYPE_MASK) != BE_REQ_USER)
            || ar->filter_type != BE_FILTER_NAME) {
        DEBUG(SSSDBG_OP_FAILURE, "Unsupported request type.\n");
        ret = EINVAL;
        goto done;
    }

    state->user_name = talloc_strdup(state, ar->filter_value);
    if (state->user_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_Strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    state->sdap_op = sdap_id_op_create(state,
                                       state->sdap_id_ctx->conn->conn_cache);
    if (state->sdap_op == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_create failed\n");
        ret = ENOMEM;
        goto done;
    }

    state->server_mode = server_mode;
    if (server_mode->ext_groups == NULL) {
        server_mode->ext_groups = talloc_zero(server_mode,
                                              struct ipa_ext_groups);
        if (server_mode->ext_groups == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
            ret = ENOMEM;
            goto done;
        }
    }

    if (server_mode->ext_groups->next_update > time(NULL)) {
        DEBUG(SSSDBG_TRACE_FUNC, "External group information still valid.\n");
        ret = ipa_add_ext_groups_step(req);
        if (ret == EOK) {
            goto done;
        } else if (ret == EAGAIN) {
            return req;
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "ipa_add_ext_groups_step failed.\n");
            goto done;
        }

    }

    subreq = sdap_id_op_connect_send(state->sdap_op, state, &ret);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_id_op_connect_send failed: %d(%s).\n",
                                  ret, strerror(ret));
        goto done;
    }

    tevent_req_set_callback(subreq, ipa_get_trusted_memberships_connect_done, req);

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

static void ipa_get_trusted_memberships_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_trusted_membership_state *state = tevent_req_data(req,
                                                struct get_trusted_membership_state);
    int ret;

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

    subreq = sdap_search_bases_send(state, state->ev, state->sdap_id_ctx->opts,
                            sdap_id_op_handle(state->sdap_op),
                            state->sdap_id_ctx->opts->sdom->group_search_bases,
                            NULL, true,
                            dp_opt_get_int(state->sdap_id_ctx->opts->basic,
                                            SDAP_ENUM_SEARCH_TIMEOUT),
                            IPA_EXT_GROUPS_FILTER,
                            NULL, NULL);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sdap_get_generic_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_get_ext_groups_done, req);
    return;

fail:
    tevent_req_error(req, ret);
    return;
}

static void ipa_get_ext_groups_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_trusted_membership_state *state = tevent_req_data(req,
                                                struct get_trusted_membership_state);
    int ret;
    hash_table_t *ext_group_hash;

    ret = sdap_search_bases_recv(subreq,
                                 state,
                                 &state->reply_count,
                                 &state->reply);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_get_ext_groups request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    DEBUG(SSSDBG_TRACE_FUNC, "[%zu] external groups found.\n",
                              state->reply_count);

    ret = process_ext_groups(state,
                             state->reply_count,
                             state->reply,
                             &ext_group_hash);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "process_ext_groups failed.\n");
        goto fail;
    }

    talloc_free(state->server_mode->ext_groups->ext_groups);
    state->server_mode->ext_groups->ext_groups = talloc_steal(
            state->server_mode->ext_groups,
            ext_group_hash);
    /* Do we have to make the update timeout configurable? */
    state->server_mode->ext_groups->next_update = time(NULL) + 10;

    ret = ipa_add_ext_groups_step(req);
    if (ret == EOK) {
        tevent_req_done(req);
        return;
    } else if (ret == EAGAIN) {
        return;
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_add_ext_groups_step failed.\n");
        goto fail;
    }

fail:
    tevent_req_error(req, ret);
    return;
}

static errno_t ipa_add_ext_groups_step(struct tevent_req *req)
{
    struct get_trusted_membership_state *state = tevent_req_data(req,
                                                struct get_trusted_membership_state);
    struct ldb_dn *user_dn;
    int ret;
    char **groups = NULL;
    struct tevent_req *subreq;

    ret = find_ipa_ext_memberships(state, state->user_name, state->user_dom,
                                   state->server_mode->ext_groups->ext_groups,
                                   &user_dn, &groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "find_ipa_ext_memberships failed.\n");
        goto fail;
    }

    if (groups == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No external groups memberships found.\n");
        state->dp_error = DP_ERR_OK;
        return EOK;
    }

    subreq = ipa_add_trusted_memberships_send(state, state->ev, state->sdap_id_ctx,
                                              user_dn, state->user_dom, groups,
                                              state->sdap_id_ctx->be->domain);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_add_trusted_memberships_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_add_trusted_memberships_done, req);
    return EAGAIN;

fail:
    tevent_req_error(req, ret);
    return ret;
}

static void ipa_add_trusted_memberships_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct get_trusted_membership_state *state = tevent_req_data(req,
                                                struct get_trusted_membership_state);
    int ret;

    ret = ipa_add_trusted_memberships_recv(subreq, &state->dp_error);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ipa_add_ad_memberships request failed.\n");
        tevent_req_error(req, ret);
        return;
    }

    state->dp_error = DP_ERR_OK;
    tevent_req_done(req);
    return;
}

errno_t ipa_get_trusted_memberships_recv(struct tevent_req *req, int *dp_error_out)
{
    struct get_trusted_membership_state *state = tevent_req_data(req,
                                                struct get_trusted_membership_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    return EOK;
}

struct add_trusted_membership_state {
    struct tevent_context *ev;
    struct sdap_id_ctx *sdap_id_ctx;
    struct sdap_id_op *sdap_op;
    struct ldb_dn *user_dn;
    struct sss_domain_info *user_dom;
    struct sss_domain_info *group_dom;
    char **groups;
    int dp_error;
    size_t iter;
    struct sdap_domain *group_sdom;
};

static void ipa_add_trusted_memberships_connect_done(struct tevent_req *subreq);
static void ipa_add_trusted_memberships_get_next(struct tevent_req *req);
static void ipa_add_trusted_memberships_get_group_done(struct tevent_req *subreq);
static struct tevent_req *ipa_add_trusted_memberships_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             struct sdap_id_ctx *sdap_id_ctx,
                                             struct ldb_dn *user_dn,
                                             struct sss_domain_info *user_dom,
                                             char **groups,
                                             struct sss_domain_info *group_dom)
{
    int ret;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct add_trusted_membership_state *state;
    bool missing_groups = false;

    req = tevent_req_create(mem_ctx, &state, struct add_trusted_membership_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }

    state->ev = ev;
    state->user_dom = user_dom;
    state->sdap_id_ctx = sdap_id_ctx;
    state->user_dn = user_dn;
    state->group_dom = group_dom;
    state->groups = groups;
    state->dp_error = -1;
    state->iter = 0;
    state->group_sdom = sdap_domain_get(sdap_id_ctx->opts, group_dom);
    if (state->group_sdom == NULL) {
        ret = EIO;
        goto done;
    }

    ret = add_ad_user_to_cached_groups(user_dn, user_dom, group_dom, groups,
                                       &missing_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "add_ad_user_to_cached_groups failed.\n");
        goto done;
    }

    if (!missing_groups) {
        DEBUG(SSSDBG_TRACE_ALL, "All groups found in cache.\n");
        ret = EOK;
        goto done;
    }

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

    tevent_req_set_callback(subreq, ipa_add_trusted_memberships_connect_done, req);

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

static void ipa_add_trusted_memberships_connect_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct add_trusted_membership_state *state = tevent_req_data(req,
                                                struct add_trusted_membership_state);
    int ret;

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

        tevent_req_error(req, ret);
        return;
    }

    state->iter = 0;
    ipa_add_trusted_memberships_get_next(req);
}

static void ipa_add_trusted_memberships_get_next(struct tevent_req *req)
{
    struct add_trusted_membership_state *state = tevent_req_data(req,
                                                struct add_trusted_membership_state);
    struct tevent_req *subreq;
    struct ldb_dn *group_dn;
    int ret;
    const struct ldb_val *val;
    bool missing_groups;
    const char *fq_name;
    char *tmp_str;

    while (state->groups[state->iter] != NULL
            && state->groups[state->iter][0] == '\0') {
        state->iter++;
    }

    if (state->groups[state->iter] == NULL) {
        ret = add_ad_user_to_cached_groups(state->user_dn, state->user_dom,
                                           state->group_dom, state->groups,
                                           &missing_groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "add_ad_user_to_cached_groups failed.\n");
            goto fail;
        }

        if (missing_groups) {
            /* this might be HBAC or sudo rule */
            DEBUG(SSSDBG_FUNC_DATA, "There are unresolved external group "
                                       "memberships even after all groups "
                                       "have been looked up on the LDAP "
                                       "server.\n");
        }
        tevent_req_done(req);
        return;
    }

    group_dn = ldb_dn_new(state, sysdb_ctx_get_ldb(state->group_dom->sysdb),
                          state->groups[state->iter]);
    if (group_dn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_new failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    val = ldb_dn_get_rdn_val(group_dn);
    if (val == NULL || val->data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Invalid group DN [%s].\n", state->groups[state->iter]);
        ret = EINVAL;
        goto fail;
    }

    fq_name = (const char *) val->data;
    if (strchr(fq_name, '@') == NULL) {
        tmp_str = sss_create_internal_fqname(state, fq_name,
                                             state->group_dom->name);
        /* keep using val->data if sss_create_internal_fqname() fails */
        if (tmp_str != NULL) {
            fq_name = tmp_str;
        }
    }

/* TODO: here is would be useful for have a filter type like BE_FILTER_DN to
 * directly fetch the group with the corresponding DN. */
    subreq = groups_get_send(state, state->ev,
                                 state->sdap_id_ctx, state->group_sdom,
                                 state->sdap_id_ctx->conn,
                                 fq_name,
                                 BE_FILTER_NAME,
                                 false, false, false);
    if (subreq == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "groups_get_send failed.\n");
        ret = ENOMEM;
        goto fail;
    }

    tevent_req_set_callback(subreq, ipa_add_trusted_memberships_get_group_done, req);
    return;

fail:
    tevent_req_error(req, ret);
}

static void ipa_add_trusted_memberships_get_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct add_trusted_membership_state *state = tevent_req_data(req,
                                                struct add_trusted_membership_state);
    int ret;

    ret = groups_get_recv(subreq, &state->dp_error, NULL);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Failed to read group [%s] from LDAP [%d](%s)\n",
              state->groups[state->iter], ret, strerror(ret));

        tevent_req_error(req, ret);
        return;
    }

    state->iter++;
    ipa_add_trusted_memberships_get_next(req);
}

static errno_t ipa_add_trusted_memberships_recv(struct tevent_req *req,
                                           int *dp_error_out)
{
    struct add_trusted_membership_state *state = tevent_req_data(req,
                                                struct add_trusted_membership_state);

    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (dp_error_out) {
        *dp_error_out = state->dp_error;
    }

    return EOK;
}

static errno_t
search_user_or_group_by_sid_str(TALLOC_CTX *mem_ctx,
                                struct sss_domain_info *domain,
                                const char *sid_str,
                                enum sysdb_member_type *_member_type,
                                struct ldb_message **_msg)
{
    errno_t ret;
    struct ldb_message *msg = NULL;
    const char *attrs[] = { SYSDB_NAME,
                            SYSDB_SID_STR,
                            SYSDB_ORIG_DN,
                            SYSDB_OBJECTCATEGORY,
                            SYSDB_CACHE_EXPIRE,
                            NULL };
    TALLOC_CTX *tmp_ctx = NULL;
    char *sanitized_sid = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    /* In theory SID shouldn't contain any special LDAP characters, but let's
     * be paranoid
     */
    ret = sss_filter_sanitize(tmp_ctx, sid_str, &sanitized_sid);
    if (ret != EOK) {
        goto done;
    }

    ret = sysdb_search_user_by_sid_str(tmp_ctx, domain,
                                       sid_str, attrs, &msg);
    if (ret == EOK) {
        *_member_type = SYSDB_MEMBER_USER;
    } else if (ret == ENOENT) {
        ret = sysdb_search_group_by_sid_str(tmp_ctx, domain,
                                            sid_str, attrs, &msg);
        if (ret == EOK) {
            *_member_type = SYSDB_MEMBER_GROUP;
        }
    }

    switch (ret) {
    case EOK:
        DEBUG(SSSDBG_TRACE_FUNC, "Found %s in sysdb\n", sid_str);
        *_msg = talloc_steal(mem_ctx, msg);
        break;
    case ENOENT:
        DEBUG(SSSDBG_TRACE_FUNC,
              "Could not find %s in sysdb\n", sid_str);
        break;
    default:
        DEBUG(SSSDBG_OP_FAILURE,
              "Error looking for %s in sysdb [%d]: %s\n",
              sid_str, ret, sss_strerror(ret));
        break;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t
ipa_ext_group_member_check(TALLOC_CTX *mem_ctx,
                           struct sss_domain_info *member_dom,
                           const char *ext_member,
                           enum sysdb_member_type *_member_type,
                           struct sysdb_attrs **_member)
{
    TALLOC_CTX *tmp_ctx = NULL;
    errno_t ret;
    uint64_t expire;
    time_t now = time(NULL);
    struct ldb_message *msg;
    struct sysdb_attrs **members;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "talloc_new() failed\n");
        return ENOMEM;
    }

    ret = search_user_or_group_by_sid_str(tmp_ctx, member_dom, ext_member,
                                          _member_type, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Error looking up sid %s: [%d]: %s\n",
               ext_member, ret, sss_strerror(ret));
        goto done;
    }

    ret = sysdb_msg2attrs(tmp_ctx, 1, &msg, &members);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not convert result to sysdb_attrs [%d]: %s\n",
               ret, sss_strerror(ret));
        goto done;
    }

    /* Return the member both expired and valid */
    *_member = talloc_steal(mem_ctx, members[0]);

    expire = ldb_msg_find_attr_as_uint64(msg, SYSDB_CACHE_EXPIRE, 0);
    if (expire != 0 && expire <= now) {
        DEBUG(SSSDBG_TRACE_FUNC, "%s is expired\n", ext_member);
        ret = EAGAIN;
        goto done;
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

/* For the IPA external member resolution, we expect a SID as the input.
 * The _recv() function output is the member and a type (user/group)
 * since nothing else can be a group member.
 */
struct ipa_ext_member_state {
    const char *ext_member;
    struct sss_domain_info *dom;

    enum sysdb_member_type member_type;
    struct sysdb_attrs *member;
};

static void ipa_ext_group_member_done(struct tevent_req *subreq);

struct tevent_req *ipa_ext_group_member_send(TALLOC_CTX *mem_ctx,
                                             struct tevent_context *ev,
                                             const char *ext_member,
                                             void *pvt)
{
    struct ipa_id_ctx *ipa_ctx;
    struct ipa_ext_member_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    struct dp_id_data *ar;
    errno_t ret;

    req = tevent_req_create(mem_ctx, &state, struct ipa_ext_member_state);
    if (req == NULL) {
        return NULL;
    }
    state->ext_member = ext_member;

    ipa_ctx = talloc_get_type(pvt, struct ipa_id_ctx);
    if (ipa_ctx == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Wrong private context!\n");
        ret = EINVAL;
        goto immediate;
    }

    state->dom = find_domain_by_sid(ipa_ctx->sdap_id_ctx->be->domain,
                                    ext_member);
    if (state->dom == NULL) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot find domain of SID [%s]\n", ext_member);
        ret = ENOENT;
        goto immediate;
    }

    ret = ipa_ext_group_member_check(state, state->dom, ext_member,
                                     &state->member_type, &state->member);
    if (ret == EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL,
              "external member %s already cached\n", ext_member);
        goto immediate;
    }

    ret = get_dp_id_data_for_sid(state, ext_member, state->dom->name, &ar);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot create the account request for [%s]\n", ext_member);
        goto immediate;
    }

    subreq = dp_req_send(state, ipa_ctx->sdap_id_ctx->be->provider,
                         ar->domain, "External Member", 0, NULL,
                         DPT_ID, DPM_ACCOUNT_HANDLER, 0, ar, NULL);
    if (subreq == NULL) {
        ret = ENOMEM;
        goto immediate;
    }
    tevent_req_set_callback(subreq, ipa_ext_group_member_done, req);

    return req;

immediate:
    if (ret != EOK) {
        tevent_req_error(req, ret);
    } else {
        tevent_req_done(req);
    }
    tevent_req_post(req, ev);
    return req;
}

static void ipa_ext_group_member_done(struct tevent_req *subreq)
{
    struct tevent_req *req = tevent_req_callback_data(subreq,
                                                      struct tevent_req);
    struct ipa_ext_member_state *state = tevent_req_data(req,
                                                struct ipa_ext_member_state);
    errno_t ret;
    struct ldb_message *msg;
    struct sysdb_attrs **members;
    struct dp_reply_std *reply;


    ret = dp_req_recv_ptr(state, subreq, struct dp_reply_std, &reply);
    talloc_free(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "dp_req_recv failed\n");
        tevent_req_error(req, ret);
        return;
    } else if (reply->dp_error != DP_ERR_OK) {
        DEBUG(SSSDBG_MINOR_FAILURE,
              "Cannot refresh data from DP: %u,%u: %s\n",
              reply->dp_error, reply->error, reply->message);
        tevent_req_error(req, EIO);
        return;
    }

    ret = search_user_or_group_by_sid_str(state,
                                          state->dom,
                                          state->ext_member,
                                          &state->member_type,
                                          &msg);
    if (ret != EOK) {
        DEBUG(ret == ENOENT ? SSSDBG_TRACE_FUNC : SSSDBG_OP_FAILURE,
              "Could not find %s in sysdb [%d]: %s\n",
              state->ext_member, ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    ret = sysdb_msg2attrs(state, 1, &msg, &members);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Could not convert result to sysdb_attrs [%d]: %s\n",
               ret, sss_strerror(ret));
        tevent_req_error(req, ret);
        return;
    }

    state->member = members[0];
    tevent_req_done(req);
}

errno_t ipa_ext_group_member_recv(TALLOC_CTX *mem_ctx,
                                  struct tevent_req *req,
                                  enum sysdb_member_type *_member_type,
                                  struct sss_domain_info **_dom,
                                  struct sysdb_attrs **_member)
{
    struct ipa_ext_member_state *state = tevent_req_data(req,
                                                struct ipa_ext_member_state);
    TEVENT_REQ_RETURN_ON_ERROR(req);

    if (_member_type != NULL) {
        *_member_type = state->member_type;
    }

    if (_dom) {
        *_dom = state->dom;
    }

    if (_member != NULL) {
        *_member = talloc_steal(mem_ctx, state->member);
    }

    return EOK;
}
