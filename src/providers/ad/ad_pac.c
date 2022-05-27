/*
    SSSD

    Authors:
        Sumit Bose <sbose@redhat.com>

    Copyright (C) 2016 Red Hat

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
#include "providers/ad/ad_pac.h"
#include "providers/ad/ad_common.h"
#include "providers/ad/ad_id.h"
#include "providers/ldap/sdap_idmap.h"
#include "providers/ldap/sdap_async_ad.h"

static errno_t find_user_entry(TALLOC_CTX *mem_ctx, struct sss_domain_info *dom,
                               struct dp_id_data *ar,
                               struct ldb_message **_msg)
{
    const char *user_attrs[] = { SYSDB_NAME, SYSDB_OBJECTCATEGORY,
                                 SYSDB_PAC_BLOB, SYSDB_PAC_BLOB_EXPIRE,
                                 NULL };
    struct ldb_message *msg;
    struct ldb_result *res;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;

    if (dom == NULL || ar == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing arguments.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    if (ar->extra_value && strcmp(ar->extra_value, EXTRA_NAME_IS_UPN) == 0) {
        ret = sysdb_search_user_by_upn(tmp_ctx, dom, false, ar->filter_value,
                                       user_attrs, &msg);
    } else {
        switch (ar->filter_type) {
        case BE_FILTER_SECID:
            ret = sysdb_search_user_by_sid_str(tmp_ctx, dom, ar->filter_value,
                                               user_attrs, &msg);
            break;
        case BE_FILTER_UUID:
            ret = sysdb_search_object_by_uuid(tmp_ctx, dom, ar->filter_value,
                                              user_attrs, &res);

            if (ret == EOK) {
                if (res->count == 1) {
                    msg = res->msgs[0];
                } else {
                    talloc_free(res);
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "Search by UUID returned multiple results.\n");
                    ret = EINVAL;
                    goto done;
                }
            }
            break;
        case BE_FILTER_NAME:
            ret = sysdb_search_user_by_name(tmp_ctx, dom, ar->filter_value,
                                            user_attrs, &msg);
            break;
        default:
            DEBUG(SSSDBG_OP_FAILURE, "Unsupported filter type [%d].\n",
                                     ar->filter_type);
            ret = EINVAL;
            goto done;
        }
    }

    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_TRACE_ALL, "No user found with filter [%s].\n",
                                    ar->filter_value);
        } else {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Looking up user in cache with filter [%s] failed.\n",
                  ar->filter_value);
        }
        goto done;
    }

    *_msg = talloc_steal(mem_ctx, msg);
    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

errno_t check_if_pac_is_available(TALLOC_CTX *mem_ctx,
                                  struct sss_domain_info *dom,
                                  struct dp_id_data *ar,
                                  struct ldb_message **_msg)
{
    struct ldb_message *msg;
    struct ldb_message_element *el;
    uint64_t pac_expires;
    time_t now;
    int ret;

    ret = find_user_entry(mem_ctx, dom, ar, &msg);
    if (ret != EOK) {
        if (ret == ENOENT) {
            DEBUG(SSSDBG_FUNC_DATA, "find_user_entry didn't find user entry.\n");
        } else {
            DEBUG(SSSDBG_OP_FAILURE, "find_user_entry failed.\n");
        }
        return ret;
    }

    el = ldb_msg_find_element(msg, SYSDB_PAC_BLOB);
    if (el == NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "No PAC available.\n");
        talloc_free(msg);
        return ENOENT;
    }

    pac_expires = ldb_msg_find_attr_as_uint64(msg, SYSDB_PAC_BLOB_EXPIRE, 0);
    now = time(NULL);
    if (pac_expires < now) {
        DEBUG(SSSDBG_TRACE_FUNC, "PAC available but too old.\n");
        talloc_free(msg);
        return ENOENT;
    }

    if (_msg != NULL) {
        *_msg = msg;
    }

    return EOK;
}

static errno_t
add_sids_from_rid_array_to_hash_table(struct dom_sid *dom_sid,
                                      struct samr_RidWithAttributeArray *groups,
                                      struct sss_idmap_ctx *idmap_ctx,
                                      hash_table_t *sid_table)
{
    enum idmap_error_code err;
    char *dom_sid_str = NULL;
    size_t dom_sid_str_len;
    char *sid_str = NULL;
    char *rid_start;
    hash_key_t key;
    hash_value_t value;
    int ret;
    size_t c;
    TALLOC_CTX *tmp_ctx = NULL;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_ULONG;

    err = sss_idmap_smb_sid_to_sid(idmap_ctx, dom_sid, &dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
        ret = EFAULT;
        goto done;
    }

    dom_sid_str_len = strlen(dom_sid_str);
    sid_str = talloc_zero_size(tmp_ctx, dom_sid_str_len + 12);
    if (sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_size failed.\n");
        ret = ENOMEM;
        goto done;
    }
    rid_start = sid_str + dom_sid_str_len;

    memcpy(sid_str, dom_sid_str, dom_sid_str_len);

    for (c = 0; c < groups->count; c++) {
        memset(rid_start, '\0', 12);
        ret = snprintf(rid_start, 12, "-%lu",
                       (unsigned long) groups->rids[c].rid);
        if (ret < 0 || ret > 12) {
            DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
            ret = EIO;
            goto done;
        }

        key.str = sid_str;
        value.ul = 0;

        ret = hash_enter(sid_table, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                      ret, hash_error_string(ret));
            ret = EIO;
            goto done;
        }

    }

    ret = EOK;

done:
    sss_idmap_free_sid(idmap_ctx, dom_sid_str);
    talloc_free(tmp_ctx);

    return ret;
}

struct resource_groups {
    struct dom_sid2 *domain_sid;
    struct samr_RidWithAttributeArray groups;
};

errno_t ad_get_sids_from_pac(TALLOC_CTX *mem_ctx,
                             struct sss_idmap_ctx *idmap_ctx,
                             struct PAC_LOGON_INFO *logon_info,
                             char **_user_sid_str,
                             char **_primary_group_sid_str,
                             size_t *_num_sids,
                             char *** _sid_list)
{
    int ret;
    size_t s;
    struct netr_SamInfo3 *info3;
    struct resource_groups resource_groups = { 0 };
    char *sid_str = NULL;
    char *msid_str = NULL;
    char *user_dom_sid_str = NULL;
    size_t user_dom_sid_str_len;
    enum idmap_error_code err;
    hash_table_t *sid_table = NULL;
    hash_key_t key;
    hash_value_t value;
    char *rid_start;
    char *user_sid_str = NULL;
    char *primary_group_sid_str = NULL;
    size_t c;
    size_t num_sids = 0;
    char **sid_list = NULL;
    struct hash_iter_context_t *iter = NULL;
    hash_entry_t *entry;
    TALLOC_CTX *tmp_ctx;

    if (idmap_ctx == NULL || logon_info == NULL
            || _num_sids == NULL || _sid_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing parameter.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    info3 = &logon_info->info3;
#ifdef HAVE_STRUCT_PAC_LOGON_INFO_RESOURCE_GROUPS
    resource_groups.domain_sid = logon_info->resource_groups.domain_sid;
    resource_groups.groups.count = logon_info->resource_groups.groups.count;
    resource_groups.groups.rids = logon_info->resource_groups.groups.rids;
#endif

    ret = sss_hash_create(tmp_ctx,
                          info3->sidcount + info3->base.groups.count + 2
                                          + resource_groups.groups.count,
                          &sid_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
        goto done;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_ULONG;

    err = sss_idmap_smb_sid_to_sid(idmap_ctx, info3->base.domain_sid,
                                   &user_dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
        ret = EFAULT;
        goto done;
    }

    user_dom_sid_str_len = strlen(user_dom_sid_str);
    sid_str = talloc_zero_size(tmp_ctx, user_dom_sid_str_len + 12);
    if (sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero_size failed.\n");
        ret = ENOMEM;
        goto done;
    }
    rid_start = sid_str + user_dom_sid_str_len;

    memcpy(sid_str, user_dom_sid_str, user_dom_sid_str_len);

    memset(rid_start, '\0', 12);
    ret = snprintf(rid_start, 12, "-%lu",
                                  (unsigned long) info3->base.rid);
    if (ret < 0 || ret > 12) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
        ret = EIO;
        goto done;
    }

    user_sid_str = talloc_strdup(tmp_ctx, sid_str);
    if (user_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key.str = sid_str;
    value.ul = 0;

    memset(rid_start, '\0', 12);
    ret = snprintf(rid_start, 12, "-%lu",
                                  (unsigned long) info3->base.primary_gid);
    if (ret < 0 || ret > 12) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
        ret = EIO;
        goto done;
    }

    primary_group_sid_str = talloc_strdup(tmp_ctx, sid_str);
    if (primary_group_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key.str = sid_str;
    value.ul = 0;

    ret = hash_enter(sid_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                  ret, hash_error_string(ret));
        ret = EIO;
        goto done;
    }

    ret = add_sids_from_rid_array_to_hash_table(info3->base.domain_sid,
                                                &info3->base.groups,
                                                idmap_ctx, sid_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "add_sids_from_rid_array_to_hash_table failed.\n");
        goto done;
    }

    for(s = 0; s < info3->sidcount; s++) {
        err = sss_idmap_smb_sid_to_sid(idmap_ctx, info3->sids[s].sid,
                                       &msid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
            ret = EFAULT;
            goto done;
        }

        key.str = msid_str;
        value.ul = 0;

        ret = hash_enter(sid_table, &key, &value);
        sss_idmap_free_sid(idmap_ctx, msid_str);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                      ret, hash_error_string(ret));
            ret = EIO;
            goto done;
        }
    }

    if (resource_groups.domain_sid != NULL) {
        ret = add_sids_from_rid_array_to_hash_table(resource_groups.domain_sid,
                                                    &resource_groups.groups,
                                                    idmap_ctx, sid_table);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "add_sids_from_rid_array_to_hash_table failed.\n");
            goto done;
        }
    }

    num_sids = hash_count(sid_table);
    sid_list = talloc_array(tmp_ctx, char *, num_sids);
    if (sid_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
        ret = ENOMEM;
        goto done;
    }

    iter = new_hash_iter_context(sid_table);
    if (iter == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "new_hash_iter_context failed.\n");
        ret = EINVAL;
        goto done;
    }

    c = 0;
    while ((entry = iter->next(iter)) != NULL) {
        sid_list[c] = talloc_strdup(sid_list, entry->key.str);
        if (sid_list[c] == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
        c++;
    }

    ret = EOK;

done:
    sss_idmap_free_sid(idmap_ctx, user_dom_sid_str);
    hash_destroy(sid_table);

    if (ret == EOK) {
        *_sid_list = talloc_steal(mem_ctx, sid_list);
        *_user_sid_str = talloc_steal(mem_ctx, user_sid_str);
        *_num_sids = num_sids;
        *_primary_group_sid_str = talloc_steal(mem_ctx, primary_group_sid_str);
    }

    talloc_free(tmp_ctx);

    return ret;
}

errno_t ad_get_pac_data_from_user_entry(TALLOC_CTX *mem_ctx,
                                        struct ldb_message *msg,
                                        struct sss_idmap_ctx *idmap_ctx,
                                        char **_username,
                                        char **user_sid,
                                        char **primary_group_sid,
                                        size_t *num_sids,
                                        char ***group_sids)
{
    int ret;
    struct ldb_message_element *el;
    struct PAC_LOGON_INFO *logon_info = NULL;
    const char *dummy;
    TALLOC_CTX *tmp_ctx = NULL;
    char *username;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    el = ldb_msg_find_element(msg, SYSDB_PAC_BLOB);
    if (el == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing PAC blob.\n");
        ret = EINVAL;
        goto done;
    }

    if (el->num_values != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Expected only one PAC blob.");
        ret = EINVAL;
        goto done;
    }

    /* PAC was already checked when it was saved in the cache, so no
     * additional check is needed here. */
    ret = ad_get_data_from_pac(tmp_ctx, 0, el->values[0].data,
                               el->values[0].length,
                               &logon_info, NULL);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_data_from_pac failed.\n");
        goto done;
    }

    dummy = ldb_msg_find_attr_as_string(msg, SYSDB_NAME, NULL);
    if (dummy == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing user name in cache entry.\n");
        ret = EINVAL;
        goto done;
    }

    username = talloc_strdup(tmp_ctx, dummy);
    if (username == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = ad_get_sids_from_pac(mem_ctx, idmap_ctx, logon_info,
                               user_sid, primary_group_sid,
                               num_sids, group_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_sids_from_pac failed.\n");
        goto done;
    }

    *_username = talloc_steal(mem_ctx, username);

    ret = EOK;
done:
    talloc_free(tmp_ctx);

    return ret;
}

struct ad_handle_pac_initgr_state {
    struct dp_id_data *ar;
    const char *err;
    int dp_error;
    int sdap_ret;
    struct sdap_options *opts;

    size_t num_missing_sids;
    char **missing_sids;
    size_t num_cached_groups;
    char **cached_groups;
    char *username;
    struct sss_domain_info *user_dom;
};

static void ad_handle_pac_initgr_lookup_sids_done(struct tevent_req *subreq);

struct tevent_req *ad_handle_pac_initgr_send(TALLOC_CTX *mem_ctx,
                                             struct be_ctx *be_ctx,
                                             struct dp_id_data *ar,
                                             struct sdap_id_ctx *id_ctx,
                                             struct sdap_domain *sdom,
                                             struct sdap_id_conn_ctx *conn,
                                             bool noexist_delete,
                                             struct ldb_message *msg)
{
    int ret;
    struct ad_handle_pac_initgr_state *state;
    struct tevent_req *req;
    struct tevent_req *subreq;
    char *user_sid;
    char *primary_group_sid;
    size_t num_sids;
    char **group_sids;
    bool use_id_mapping;

    req = tevent_req_create(mem_ctx, &state,
                            struct ad_handle_pac_initgr_state);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "tevent_req_create failed.\n");
        return NULL;
    }
    state->user_dom = sdom->dom;
    state->opts = id_ctx->opts;

    /* The following variables are currently unused because no sub-request
     * returns any of them. But they are needed to allow the same signature as
     * sdap_handle_acct_req_recv() from the alternative group-membership
     * lookup path. */
    state->err = NULL;
    state->dp_error = DP_ERR_OK;
    state->sdap_ret = EOK;

    ret = ad_get_pac_data_from_user_entry(state, msg,
                                          id_ctx->opts->idmap_ctx->map,
                                          &state->username,
                                          &user_sid, &primary_group_sid,
                                          &num_sids, &group_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "ad_get_pac_data_from_user_entry failed.\n");
        goto done;
    }

    use_id_mapping = sdap_idmap_domain_has_algorithmic_mapping(
                                                       id_ctx->opts->idmap_ctx,
                                                       sdom->dom->name,
                                                       sdom->dom->domain_id);
    if (use_id_mapping
            && sdom->dom->ignore_group_members == false) {
        /* In contrast to the tokenGroups based group-membership lookup the
         * PAC based approach can be used for sub-domains with id-mapping as
         * well because the PAC will only contain groups which are valid in
         * the target domain, i.e. it will not contain domain-local groups for
         * domains other than the user domain. This means the groups must not
         * be looked up immediately to determine if they are domain-local or
         * not.
         *
         * Additionally, as a temporary workaround until
         * https://fedorahosted.org/sssd/ticket/2522 is fixed, we also fetch
         * the group object if group members are ignored to avoid having to
         * transfer and retain members when the fake tokengroups object
         * without name is replaced by the full group object.
         */

        DEBUG(SSSDBG_TRACE_ALL, "Running PAC processing with id-mapping.\n");

        ret = sdap_ad_save_group_membership_with_idmapping(state->username,
                                                        state->opts,
                                                        sdom->dom,
                                                        id_ctx->opts->idmap_ctx,
                                                        num_sids, group_sids);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_ad_save_group_membership_with_idmapping failed.\n");
        }

        /* this path only includes cache operation, so we can finish the
         * request immediately */
        goto done;
    } else {

        DEBUG(SSSDBG_TRACE_ALL, "Running PAC processing with external IDs.\n");

        ret = sdap_ad_tokengroups_get_posix_members(state, sdom->dom,
                                                    num_sids, group_sids,
                                                    &state->num_missing_sids,
                                                    &state->missing_sids,
                                                    &state->num_cached_groups,
                                                    &state->cached_groups);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sdap_ad_tokengroups_get_posix_members failed.\n");
            goto done;
        }

        /* download missing SIDs */
        subreq = sdap_ad_resolve_sids_send(state, be_ctx->ev, id_ctx,
                                           conn,
                                           id_ctx->opts, sdom->dom,
                                           state->missing_sids);
        if (subreq == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sdap_ad_resolve_sids_send failed.\n");
            ret = ENOMEM;
            goto done;
        }

        tevent_req_set_callback(subreq, ad_handle_pac_initgr_lookup_sids_done,
                                req);

    }

    return req;

done:
    if (ret == EOK) {
        tevent_req_done(req);
    } else {
        tevent_req_error(req, ret);
    }
    tevent_req_post(req, be_ctx->ev);

    return req;
}

static void ad_handle_pac_initgr_lookup_sids_done(struct tevent_req *subreq)
{
    struct ad_handle_pac_initgr_state *state;
    struct tevent_req *req = NULL;
    errno_t ret;
    char **cached_groups;
    size_t num_cached_groups;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct ad_handle_pac_initgr_state);

    ret = sdap_ad_resolve_sids_recv(subreq);
    talloc_zfree(subreq);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to resolve missing SIDs "
                                   "[%d]: %s\n", ret, strerror(ret));
        goto done;
    }

    ret = sdap_ad_tokengroups_get_posix_members(state, state->user_dom,
                                                state->num_missing_sids,
                                                state->missing_sids,
                                                NULL, NULL,
                                                &num_cached_groups,
                                                &cached_groups);
    if (ret != EOK){
        DEBUG(SSSDBG_MINOR_FAILURE,
              "sdap_ad_tokengroups_get_posix_members failed [%d]: %s\n",
              ret, strerror(ret));
        goto done;
    }

    state->cached_groups = concatenate_string_array(state,
                                                    state->cached_groups,
                                                    state->num_cached_groups,
                                                    cached_groups,
                                                    num_cached_groups);
    if (state->cached_groups == NULL) {
        ret = ENOMEM;
        goto done;
    }

    /* update membership of existing groups */
    ret = sdap_ad_tokengroups_update_members(state->username,
                                             state->user_dom->sysdb,
                                             state->user_dom,
                                             state->cached_groups);
    if (ret != EOK) {
        DEBUG(SSSDBG_MINOR_FAILURE, "Membership update failed [%d]: %s\n",
                                     ret, strerror(ret));
        goto done;
    }

done:
    if (ret != EOK) {
        tevent_req_error(req, ret);
        return;
    }

    tevent_req_done(req);
}

errno_t ad_handle_pac_initgr_recv(struct tevent_req *req,
                                  int *_dp_error, const char **_err,
                                  int *sdap_ret)
{
    struct ad_handle_pac_initgr_state *state;

    state = tevent_req_data(req, struct ad_handle_pac_initgr_state);

    if (_dp_error) {
        *_dp_error = state->dp_error;
    }

    if (_err) {
        *_err = state->err;
    }

    if (sdap_ret) {
        *sdap_ret = state->sdap_ret;
    }
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}
