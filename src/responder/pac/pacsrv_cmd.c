/*
   SSSD

   PAC Responder

   Copyright (C) Sumit Bose <sbose@redhat.com> 2012
                 Jan Zeleny <jzeleny@redhat.com> 2012

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
#include "responder/pac/pacsrv.h"
#include "confdb/confdb.h"

static errno_t pac_cmd_done(struct cli_ctx *cctx, int cmd_ret)
{
    int ret;

    if (cmd_ret == EAGAIN) {
        /* async processing, just return here */
        return EOK;
    }

    ret = sss_packet_new(cctx->creq, 0, sss_packet_get_cmd(cctx->creq->in),
                         &cctx->creq->out);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_packet_new failed [%d][%s].\n",
                                  ret, strerror(ret));
        return ret;
    }

    sss_packet_set_error(cctx->creq->out, cmd_ret);

    sss_cmd_done(cctx, NULL);

    return EOK;
}

struct pac_req_ctx {
    struct cli_ctx *cctx;
    struct pac_ctx *pac_ctx;
    const char *domain_name;
    const char *user_name;
    struct sss_domain_info *dom;

    struct PAC_LOGON_INFO *logon_info;
    struct dom_sid2 *domain_sid;

    size_t del_grp_count;
    struct grp_info *del_grp_list;

    size_t add_sid_count;
    char **add_sids;

    hash_table_t *sid_table;
    char *user_sid_str;
    char *user_dom_sid_str;
    char *primary_group_sid_str;
};

static errno_t pac_resolve_sids_next(struct pac_req_ctx *pr_ctx);
static void pac_lookup_sids_done(struct tevent_req *req);
static struct tevent_req *pac_lookup_sids_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct pac_req_ctx *pr_ctx,
                                               struct pac_ctx *pac_ctx,
                                               hash_table_t *sid_table);
static errno_t pac_lookup_sids_recv(struct tevent_req *req);
static void pac_add_user_next(struct pac_req_ctx *pr_ctx);
static void pac_get_domains_done(struct tevent_req *req);
static errno_t pac_user_get_grp_info(TALLOC_CTX *mem_ctx,
                                     struct pac_req_ctx *pr_ctx,
                                     size_t *_del_grp_count,
                                     struct grp_info **_del_grp_list,
                                     size_t *_add_sid_count,
                                     char ***_add_sids);
static errno_t save_pac_user(struct pac_req_ctx *pr_ctx);
static void pac_get_group_done(struct tevent_req *subreq);
static errno_t pac_save_memberships_next(struct tevent_req *req);
static errno_t pac_store_membership(struct pac_req_ctx *pr_ctx,
                                    struct ldb_dn *user_dn,
                                    const char *grp_sid_str,
                                    struct sss_domain_info *grp_dom);
struct tevent_req *pac_save_memberships_send(struct pac_req_ctx *pr_ctx);
static void pac_save_memberships_done(struct tevent_req *req);


static errno_t pac_add_pac_user(struct cli_ctx *cctx)
{
    int ret;
    uint8_t *body;
    size_t blen;
    struct pac_req_ctx *pr_ctx;
    struct tevent_req *req;
    enum idmap_error_code err;

    sss_packet_get_body(cctx->creq->in, &body, &blen);

    pr_ctx = talloc_zero(cctx, struct pac_req_ctx);
    if (pr_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    pr_ctx->cctx = cctx;

    pr_ctx->pac_ctx = talloc_get_type(cctx->rctx->pvt_ctx,  struct pac_ctx);
    if (pr_ctx->pac_ctx == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "Cannot find pac responder context.\n");
        return EINVAL;
    }

    ret = get_data_from_pac(pr_ctx, body, blen,
                            &pr_ctx->logon_info);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_data_from_pac failed.\n");
        goto done;
    }

    pr_ctx->domain_name = pr_ctx->logon_info->info3.base.logon_domain.string;
    if (pr_ctx->domain_name == NULL) {
        DEBUG(SSSDBG_FATAL_FAILURE, "No domain name in PAC");
        ret = EINVAL;
        goto done;
    }

    if (pr_ctx->logon_info->info3.base.account_name.string == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_FATAL_FAILURE, "Missing account name in PAC.\n");
        goto done;
    }

    /* To be compatible with winbind based lookups we have to use lower case
     * names only, effectively making the domain case-insenvitive. */
    pr_ctx->user_name = sss_tc_utf8_str_tolower(pr_ctx,
                            pr_ctx->logon_info->info3.base.account_name.string);
    if (pr_ctx->user_name == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_FATAL_FAILURE, "sss_tc_utf8_str_tolower failed.\n");
        goto done;
    }

    err = sss_idmap_smb_sid_to_sid(pr_ctx->pac_ctx->idmap_ctx,
                                   pr_ctx->logon_info->info3.base.domain_sid,
                                   &pr_ctx->user_dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
        ret = EFAULT;
        goto done;
    }

    talloc_steal(pr_ctx, pr_ctx->user_dom_sid_str);

    ret = responder_get_domain_by_id(cctx->rctx, pr_ctx->user_dom_sid_str,
                                     &pr_ctx->dom);
    if (ret == EAGAIN || ret == ENOENT) {
        req = sss_dp_get_domains_send(cctx->rctx, cctx->rctx, true,
                                      pr_ctx->domain_name);
        if (req == NULL) {
            ret = ENOMEM;
        } else {
            tevent_req_set_callback(req, pac_get_domains_done, pr_ctx);
            ret = EAGAIN;
        }
        goto done;
    } else if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "responder_get_domain_by_id failed.\n");
        goto done;
    }

    ret = pac_resolve_sids_next(pr_ctx);

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    return pac_cmd_done(cctx, ret);
}

static void pac_get_domains_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req,
                                                          struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    int ret;

    ret = sss_dp_get_domains_recv(req);
    talloc_free(req);
    if (ret != EOK) {
        goto done;
    }

    ret = responder_get_domain_by_id(cctx->rctx, pr_ctx->user_dom_sid_str,
                                     &pr_ctx->dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "Corresponding domain [%s] has not been "
                                  "found\n", pr_ctx->user_dom_sid_str);
        ret = ENOENT;
        goto done;
    }

    ret = pac_resolve_sids_next(pr_ctx);

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    pac_cmd_done(cctx, ret);
}

static errno_t pac_resolve_sids_next(struct pac_req_ctx *pr_ctx)
{
    int ret;
    struct tevent_req *req;

    ret = get_sids_from_pac(pr_ctx, pr_ctx->pac_ctx, pr_ctx->logon_info,
                            &pr_ctx->user_sid_str,
                            &pr_ctx->primary_group_sid_str,
                            &pr_ctx->sid_table);
    if (ret != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "get_sids_from_pac failed.\n");
        return ret;
    }

    req = pac_lookup_sids_send(pr_ctx, pr_ctx->cctx->ev, pr_ctx,
                               pr_ctx->pac_ctx, pr_ctx->sid_table);
    if (req == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "pac_lookup_sids_send failed.\n");
        return ENOMEM;
    }

    tevent_req_set_callback(req, pac_lookup_sids_done, pr_ctx);

    ret = EAGAIN;


    return ret;
}

static void pac_lookup_sids_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req, struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    errno_t ret;
    unsigned long count;
    hash_entry_t *entries;
    hash_key_t key;
    hash_value_t value;
    size_t c;
    struct sss_domain_info *dom;
    uint64_t id;
    struct ldb_result *msg;

    ret = pac_lookup_sids_recv(req);
    talloc_zfree(req);

    if (ret != EOK) {
        talloc_free(pr_ctx);
        pac_cmd_done(cctx, ret);
        return;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_ULONG;

    ret = hash_entries(pr_ctx->sid_table, &count, &entries);
    for (c = 0; c < count; c++) {
        if (entries[c].value.ul == 0) {
            ret =responder_get_domain_by_id(cctx->rctx,
                                            entries[c].key.str, &dom);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "No domain found for SID [%s].\n",
                                          entries[c].key.str);
                continue;
            }

            msg = NULL;
            ret = sysdb_search_object_by_sid(pr_ctx, dom, entries[c].key.str,
                                             NULL, &msg);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_object_by_sid " \
                                          "failed.\n");
                continue;
            }

            if (msg->count == 0) {
                DEBUG(SSSDBG_OP_FAILURE, "No entry found for SID [%s].\n",
                                          entries[c].key.str);
                continue;
            } else if (msg->count > 1) {
                DEBUG(SSSDBG_CRIT_FAILURE, "More then one result returned " \
                                            "for SID [%s].\n",
                                            entries[c].key.str);
                talloc_free(msg);
                pac_cmd_done(cctx, EINVAL);
                return;
            }

            id = ldb_msg_find_attr_as_uint64(msg->msgs[0],
                                             SYSDB_UIDNUM, 0);
            if (id == 0) {
                id = ldb_msg_find_attr_as_uint64(msg->msgs[0],
                                                 SYSDB_GIDNUM, 0);
            }

            if (id == 0) {
                DEBUG(SSSDBG_OP_FAILURE, "No ID found in entry.\n");
                talloc_free(msg);
                continue;
            }

            key.str = entries[c].key.str;
            value.ul = id;

            ret = hash_enter(pr_ctx->sid_table, &key, &value);
            if (ret != HASH_SUCCESS) {
                DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                          ret, hash_error_string(ret));
                continue;
            }
            talloc_free(msg);
        }
    }

    pac_add_user_next(pr_ctx);
}

static void pac_add_user_next(struct pac_req_ctx *pr_ctx)
{
    int ret;
    struct tevent_req *req;
    struct cli_ctx *cctx = pr_ctx->cctx;

    ret = save_pac_user(pr_ctx);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "save_pac_user failed.\n");
        goto done;
    }

    ret = pac_user_get_grp_info(pr_ctx, pr_ctx, &pr_ctx->del_grp_count,
                                &pr_ctx->del_grp_list,
                                &pr_ctx->add_sid_count, &pr_ctx->add_sids);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pac_user_get_grp_info failed.\n");
        goto done;
    }

    req = pac_save_memberships_send(pr_ctx);
    if (req == NULL) {
        ret = ENOMEM;
        goto done;
    }

    tevent_req_set_callback(req, pac_save_memberships_done, pr_ctx);

    ret = EAGAIN;

done:
    if (ret != EAGAIN) {
        talloc_free(pr_ctx);
    }
    pac_cmd_done(cctx, ret);
}

static errno_t pac_user_get_grp_info(TALLOC_CTX *mem_ctx,
                                     struct pac_req_ctx *pr_ctx,
                                     size_t *_del_grp_count,
                                     struct grp_info **_del_grp_list,
                                     size_t *_add_sid_count,
                                     char ***_add_sids)
{
    struct sysdb_ctx *sysdb;
    int ret;
    TALLOC_CTX *tmp_ctx = NULL;
    struct ldb_result *res = NULL;
    size_t c;
    const char *tmp_str;

    size_t add_sid_count = 0;
    char **add_sids = NULL;

    size_t del_idx;
    size_t del_grp_count = 0;
    struct grp_info *del_grp_list = NULL;

    const char *cur_sid;
    hash_key_t key;
    hash_value_t value;

    struct hash_iter_context_t *iter = NULL;
    hash_entry_t *entry;

    sysdb = pr_ctx->dom->sysdb;
    if (sysdb == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal: Sysdb CTX not found for this domain!\n");
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        goto done;
    }

    ret = sysdb_initgroups(tmp_ctx, pr_ctx->dom, pr_ctx->user_name, &res);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_initgroups failed.\n");
        goto done;
    }

    if (res->count == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_initgroups did not found [%s].\n",
                                  pr_ctx->user_name);
        ret = ENOENT;
        goto done;
    }

    /* First result is the user entry then the groups follow */
    if (res->count > 1) {
        del_grp_count = res->count - 1;
        del_grp_list = talloc_zero_array(tmp_ctx, struct grp_info,
                                         del_grp_count);
        if (del_grp_list == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }
        del_idx = 0;

        key.type = HASH_KEY_STRING;

        for (c = 0; c < (res->count - 1); c++) {
            cur_sid = ldb_msg_find_attr_as_string(res->msgs[c + 1],
                                                  SYSDB_SID_STR, NULL);
            if (cur_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "Missing SID in group entry.\n");
                ret = EINVAL;
                goto done;
            }

            key.str = discard_const(cur_sid);
            ret = hash_lookup(pr_ctx->sid_table, &key, &value);
            if (ret == HASH_SUCCESS) {
                DEBUG(SSSDBG_TRACE_ALL, "User [%s] already member of group " \
                                         "with SID [%s].\n",
                                         pr_ctx->user_name, cur_sid);

                ret = hash_delete(pr_ctx->sid_table, &key);
                if (ret != HASH_SUCCESS) {
                    DEBUG(SSSDBG_OP_FAILURE, "Failed to remove hash entry.\n");
                    ret = EIO;
                    goto done;
                }
            } else if (ret == HASH_ERROR_KEY_NOT_FOUND) {
                DEBUG(SSSDBG_TRACE_INTERNAL, "Group with SID [%s] is not in " \
                                              "the PAC anymore, membership " \
                                              "must be removed.\n", cur_sid);

                tmp_str = ldb_msg_find_attr_as_string(res->msgs[c + 1],
                                                      SYSDB_ORIG_DN, NULL);
                if (tmp_str != NULL) {
                    del_grp_list[del_idx].orig_dn = talloc_strdup(del_grp_list,
                                                                  tmp_str);
                    if (del_grp_list[del_idx].orig_dn == NULL) {
                        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                        ret = ENOMEM;
                        goto done;
                    }
                }

                del_grp_list[del_idx].dn = ldb_dn_copy(del_grp_list,
                                                       res->msgs[c + 1]->dn);
                if (del_grp_list[del_idx].dn == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "ldb_dn_copy failed.\n");
                    ret = ENOMEM;
                    goto done;
                }

                del_idx++;
            }
        }
        del_grp_count = del_idx;
    }

    add_sid_count = hash_count(pr_ctx->sid_table);
    if (add_sid_count > 0) {
        add_sids = talloc_array(tmp_ctx, char *, add_sid_count);
        if (add_sids == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_array failed.\n");
            ret = ENOMEM;
            goto done;
        }

        iter = new_hash_iter_context(pr_ctx->sid_table);
        c = 0;
        while ((entry = iter->next(iter)) != NULL) {
            if (strcmp(entry->key.str, pr_ctx->user_sid_str) != 0) {
                add_sids[c] = talloc_strdup(add_sids, entry->key.str);
                if (add_sids[c] == NULL) {
                    DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
                    ret = ENOMEM;
                    goto done;
                }
                DEBUG(SSSDBG_TRACE_ALL, "SID [%s] added to add_sids " \
                                         "list.\n", entry->key.str);
                c++;
            }
        }
        add_sid_count = c;
    }


    *_del_grp_count = del_grp_count;
    *_del_grp_list = talloc_steal(mem_ctx, del_grp_list);
    *_add_sid_count = add_sid_count;
    *_add_sids = talloc_steal(mem_ctx, add_sids);

    ret = EOK;

done:
    talloc_free(iter);
    talloc_free(tmp_ctx);

    return ret;
}

static errno_t save_pac_user(struct pac_req_ctx *pr_ctx)
{
    struct sysdb_ctx *sysdb;
    int ret;
    const char *attrs[] = {SYSDB_NAME, SYSDB_NAME_ALIAS, SYSDB_UIDNUM,
                           SYSDB_GIDNUM, SYSDB_GECOS, SYSDB_HOMEDIR,
                           SYSDB_SHELL, SYSDB_ORIG_DN, SYSDB_CACHEDPWD, NULL};
    struct ldb_message *msg;
    struct passwd *pwd = NULL;
    TALLOC_CTX *tmp_ctx = NULL;
    struct sysdb_attrs *user_attrs = NULL;

    sysdb = pr_ctx->dom->sysdb;
    if (sysdb == NULL) {
        ret = EINVAL;
        DEBUG(SSSDBG_FATAL_FAILURE, "Fatal: Sysdb CTX not found for this domain!\n");
        goto done;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        ret = ENOMEM;
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        goto done;
    }

    ret = get_pwd_from_pac(tmp_ctx, pr_ctx->dom, pr_ctx->user_sid_str,
                           pr_ctx->primary_group_sid_str, pr_ctx->sid_table,
                           pr_ctx->logon_info, &pwd, &user_attrs);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "get_pwd_from_pac failed.\n");
        goto done;
    }

    ret = sysdb_search_user_by_uid(tmp_ctx, pr_ctx->dom, pwd->pw_uid, attrs,
                                   &msg);
    if (ret == ENOENT) {
        if (pwd->pw_gid == 0 && !pr_ctx->dom->mpg) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Primary group RID from the PAC " \
                                        "cannot be translated into a GID for " \
                                        "user [%s]. Typically this happens " \
                                        "when UIDs and GIDs are read from AD " \
                                        "and the primary AD group does not " \
                                        "have a GID assigned. Make sure the " \
                                        "user is created by the ID provider " \
                                        "before GSSAPI based authentication " \
                                        "is used in this case.", pwd->pw_name);
            ret = EINVAL;
            goto done;
        }

        ret = sysdb_store_user(pr_ctx->dom, pwd->pw_name, NULL,
                               pwd->pw_uid, pwd->pw_gid, pwd->pw_gecos,
                               pwd->pw_dir,
                               pwd->pw_shell, NULL, user_attrs, NULL,
                               pr_ctx->dom->user_timeout, 0);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_store_user failed [%d][%s].\n",
                                      ret, strerror(ret));
            goto done;
        }
    } else if (ret != EOK && ret != ENOENT) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_id failed.\n");
        goto done;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

struct pac_save_memberships_state {
    size_t sid_iter;
    struct ldb_dn *user_dn;

    struct pac_req_ctx *pr_ctx;
};

static errno_t
pac_save_memberships_delete(struct pac_save_memberships_state *state);

struct tevent_req *pac_save_memberships_send(struct pac_req_ctx *pr_ctx)
{
    struct pac_save_memberships_state *state;
    struct sss_domain_info *dom = pr_ctx->dom;
    struct tevent_req *req;
    errno_t ret;
    char *dom_name = NULL;
    struct ldb_message *msg;

    req = tevent_req_create(pr_ctx, &state, struct pac_save_memberships_state);
    if (req == NULL) {
        return NULL;
    }

    state->sid_iter = 0;

    dom_name = sss_get_domain_name(state, pr_ctx->user_name, dom);
    if (dom_name == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_sprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_search_user_by_name(state, dom, dom_name, NULL, &msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_search_user_by_name failed " \
                                  "[%d][%s].\n", ret, strerror(ret));
        goto done;
    }

    state->user_dn = msg->dn;
    state->pr_ctx = pr_ctx;

    ret = pac_save_memberships_delete(state);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pac_save_memberships_delete failed.\n");
        goto done;
    }

    ret = pac_save_memberships_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
        tevent_req_post(req, pr_ctx->cctx->ev);
    }

done:
    talloc_free(dom_name);
    if (ret != EOK && ret != EAGAIN) {
        tevent_req_error(req, ret);
        tevent_req_post(req, pr_ctx->cctx->ev);
    }

    return req;
}

static errno_t
pac_save_memberships_delete(struct pac_save_memberships_state *state)
{
    int ret;
    int sret;
    size_t c;
    struct pac_req_ctx *pr_ctx;
    bool in_transaction = false;
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *user_attrs = NULL;

    pr_ctx = state->pr_ctx;

    if (pr_ctx->del_grp_count == 0) {
        return EOK;
    }

    if (pr_ctx->del_grp_list == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing group list.\n");
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    ret = sysdb_transaction_start(pr_ctx->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_start failed.\n");
        goto done;
    }
    in_transaction = true;

    for (c = 0; c < pr_ctx->del_grp_count; c++) {
        /* If there is a failure for one group we still try to remove the
         * remaining groups. */
        ret = sysdb_mod_group_member(pr_ctx->dom, state->user_dn,
                                     pr_ctx->del_grp_list[c].dn,
                                     LDB_FLAG_MOD_DELETE);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_mod_group_member failed for " \
                                      "user [%s] and group[%s].\n",
                                      ldb_dn_get_linearized(state->user_dn),
                                      ldb_dn_get_linearized(
                                                  pr_ctx->del_grp_list[c].dn));
            continue;
        }

        if (pr_ctx->del_grp_list[c].orig_dn != NULL) {
            user_attrs = sysdb_new_attrs(tmp_ctx);
            if (user_attrs == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
                continue;
            }

            ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                                         pr_ctx->del_grp_list[c].orig_dn);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
                continue;
            }

            ret = sysdb_set_entry_attr(pr_ctx->dom->sysdb, state->user_dn, user_attrs,
                                       LDB_FLAG_MOD_DELETE);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
                continue;
            }
            talloc_free(user_attrs);
        }
    }

    ret = sysdb_transaction_commit(pr_ctx->dom->sysdb);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_commit failed.\n");
        goto done;
    }
    in_transaction = false;

    ret = EOK;
done:
    if (in_transaction) {
        sret = sysdb_transaction_cancel(pr_ctx->dom->sysdb);
        if (sret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_transaction_cancel failed.\n");
        }
    }

    talloc_free(tmp_ctx);

    return ret;
}

static errno_t pac_save_memberships_next(struct tevent_req *req)
{
    errno_t ret;
    char *sid;
    struct sss_domain_info *grp_dom;
    struct tevent_req *subreq;
    struct pac_save_memberships_state *state;
    struct pac_req_ctx *pr_ctx;

    state = tevent_req_data(req, struct pac_save_memberships_state);
    pr_ctx = state->pr_ctx;

    if (pr_ctx->add_sid_count == 0) {
        return EOK;
    }

    if (pr_ctx->add_sids == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing list of SIDs.\n");
        return EINVAL;
    }

    while (state->sid_iter < pr_ctx->add_sid_count) {
        sid = pr_ctx->add_sids[state->sid_iter];
        ret = responder_get_domain_by_id(pr_ctx->pac_ctx->rctx, sid, &grp_dom);
        if (ret != EOK) {
            DEBUG(SSSDBG_MINOR_FAILURE, "responder_get_domain_by_id failed, " \
                                         "will try next group\n");
            state->sid_iter++;
            continue;
        }

        ret = pac_store_membership(state->pr_ctx, state->user_dn, sid, grp_dom);
        if (ret == EOK) {
            state->sid_iter++;
            continue;
        } else if (ret == ENOENT) {
            subreq = sss_dp_get_account_send(state, pr_ctx->cctx->rctx,
                                             grp_dom, true,
                                             SSS_DP_SECID, sid, 0, NULL);
            if (subreq == NULL) {
                ret = ENOMEM;
                goto done;
            }
            tevent_req_set_callback(subreq, pac_get_group_done, req);

            return EAGAIN;
        } else  {
            DEBUG(SSSDBG_OP_FAILURE, "pac_store_membership failed, "
                                      "trying next group.\n");
            state->sid_iter++;
            continue;
        }
    }

    ret = EOK;
done:
    return ret;
}

static void pac_get_group_done(struct tevent_req *subreq)
{
    struct tevent_req *req;
    struct pac_save_memberships_state *state;

    req = tevent_req_callback_data(subreq, struct tevent_req);
    state = tevent_req_data(req, struct pac_save_memberships_state);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;
    char *sid;
    struct sss_domain_info *grp_dom;
    struct pac_req_ctx *pr_ctx = state->pr_ctx;

    ret = sss_dp_get_account_recv(req, subreq,
                                  &err_maj, &err_min,
                                  &err_msg);
    talloc_zfree(subreq);
    talloc_zfree(err_msg);
    if (ret != EOK) {
        goto error;
    }

    sid = pr_ctx->add_sids[state->sid_iter];
    ret = responder_get_domain_by_id(pr_ctx->pac_ctx->rctx,sid, &grp_dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "responder_get_domain_by_id failed.\n");
        goto error;
    }

    ret = pac_store_membership(state->pr_ctx, state->user_dn, sid, grp_dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "pac_store_membership failed, "
                                  "trying next group.\n");
    }
    state->sid_iter++;

    ret = pac_save_memberships_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        goto error;
    }

    return;

error:
    tevent_req_error(req, ret);
}

static errno_t
pac_store_membership(struct pac_req_ctx *pr_ctx,
                     struct ldb_dn *user_dn,
                     const char *grp_sid_str,
                     struct sss_domain_info *grp_dom)
{
    TALLOC_CTX *tmp_ctx;
    struct sysdb_attrs *user_attrs;
    struct ldb_result *group;
    errno_t ret;
    const char *orig_group_dn;
    const char *group_attrs[] = { SYSDB_ORIG_DN, SYSDB_OBJECTCLASS, NULL };
    const char *oc;

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        return ENOMEM;
    }

    ret = sysdb_search_object_by_sid(tmp_ctx, grp_dom, grp_sid_str,
                                     group_attrs, &group);
    if (ret != EOK) {
        DEBUG(SSSDBG_TRACE_INTERNAL, "sysdb_search_object_by_sid " \
                                      "for SID [%s] failed [%d][%s].\n",
                                      grp_sid_str, ret, strerror(ret));
        goto done;
    }

    if (group->count != 1) {
        DEBUG(SSSDBG_OP_FAILURE, "Unexpected number of groups returned.\n");
        ret = EINVAL;
        goto done;
    }

    oc = ldb_msg_find_attr_as_string(group->msgs[0], SYSDB_OBJECTCLASS, NULL);
    if (oc == NULL || strcmp(oc, SYSDB_GROUP_CLASS) != 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Return object does not have group " \
                                  "objectclass.\n");
        ret = EINVAL;
        goto done;
    }

    DEBUG(SSSDBG_TRACE_ALL, "Adding user [%s] to group [%s][%s].\n",
                             ldb_dn_get_linearized(user_dn), grp_sid_str,
                             ldb_dn_get_linearized(group->msgs[0]->dn));
    ret = sysdb_mod_group_member(grp_dom, user_dn, group->msgs[0]->dn,
                                 LDB_FLAG_MOD_ADD);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_mod_group_member failed user [%s] " \
                                  "group [%s].\n",
                                  ldb_dn_get_linearized(user_dn),
                                  ldb_dn_get_linearized(group->msgs[0]->dn));
        goto done;
    }

    orig_group_dn = ldb_msg_find_attr_as_string(group->msgs[0], SYSDB_ORIG_DN,
                                                NULL);
    if (orig_group_dn != NULL) {
        DEBUG(SSSDBG_TRACE_ALL, "Adding original group DN [%s] to user [%s].\n",
                                 orig_group_dn,
                                 ldb_dn_get_linearized(user_dn));
        user_attrs = sysdb_new_attrs(tmp_ctx);
        if (user_attrs == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
            ret = ENOMEM;
            goto done;
        }

        ret = sysdb_attrs_add_string(user_attrs, SYSDB_ORIG_MEMBEROF,
                                     orig_group_dn);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
            goto done;
        }

        ret = sysdb_set_entry_attr(pr_ctx->dom->sysdb, user_dn, user_attrs,
                                   LDB_FLAG_MOD_ADD);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "sysdb_set_entry_attr failed.\n");
            goto done;
        }
    } else {
        DEBUG(SSSDBG_MINOR_FAILURE, "Original DN not available for group " \
                                     "[%s][%s].\n", grp_sid_str,
                                     ldb_dn_get_linearized(group->msgs[0]->dn));
    }

done:
    talloc_free(tmp_ctx);
    return ret;
}

static errno_t pac_save_memberships_recv(struct tevent_req *subreq)
{
    TEVENT_REQ_RETURN_ON_ERROR(subreq);

    return EOK;
}

static void pac_save_memberships_done(struct tevent_req *req)
{
    struct pac_req_ctx *pr_ctx = tevent_req_callback_data(req, struct pac_req_ctx);
    struct cli_ctx *cctx = pr_ctx->cctx;
    errno_t ret;

    ret = pac_save_memberships_recv(req);
    talloc_zfree(req);

    talloc_free(pr_ctx);
    pac_cmd_done(cctx, ret);
}

struct pac_lookup_sids_state {
    struct pac_ctx *pac_ctx;
    struct pac_req_ctx *pr_ctx;
    hash_table_t *sid_table;
    struct hash_iter_context_t *iter;
};

static errno_t pac_lookup_sids_next(struct tevent_req *req);
static void pac_lookup_sids_next_done(struct tevent_req *subreq);

static struct tevent_req *pac_lookup_sids_send(TALLOC_CTX *mem_ctx,
                                               struct tevent_context *ev,
                                               struct pac_req_ctx *pr_ctx,
                                               struct pac_ctx *pac_ctx,
                                               hash_table_t *sid_table)
{
    struct tevent_req *req;
    struct pac_lookup_sids_state *state;
    int ret;

    req = tevent_req_create(mem_ctx, &state, struct pac_lookup_sids_state);
    if (req == NULL) {
        return NULL;
    }

    state->pac_ctx = pac_ctx;
    state->pr_ctx = pr_ctx;
    state->sid_table = sid_table;
    state->iter = talloc_steal(state, new_hash_iter_context(state->sid_table));

    ret = pac_lookup_sids_next(req);

    if (ret != EAGAIN) {
        if (ret == EOK) {
            tevent_req_done(req);
        } else {
            tevent_req_error(req, ret);
        }
        tevent_req_post(req, ev);
    }

    return req;
}


static errno_t pac_lookup_sids_next(struct tevent_req *req)
{
    struct pac_lookup_sids_state *state;
    state = tevent_req_data(req, struct pac_lookup_sids_state);
    hash_entry_t *entry;
    struct tevent_req *subreq;
    struct sss_domain_info *dom;
    int ret;

    while ((entry = state->iter->next(state->iter)) != NULL) {
        if (entry->value.ul == 0) {
            ret = responder_get_domain_by_id(state->pac_ctx->rctx,
                                             entry->key.str, &dom);
            if (ret == EOK && dom != NULL) {
                subreq = sss_dp_get_account_send(state,
                                                 state->pr_ctx->cctx->rctx,
                                                 dom, true,
                                                 SSS_DP_SECID, entry->key.str,
                                                 0, NULL);
                if (subreq == NULL) {
                    return ENOMEM;
                }
                tevent_req_set_callback(subreq, pac_lookup_sids_next_done, req);
                return EAGAIN;
            }
        }
    }

    return EOK;
}

static void pac_lookup_sids_next_done(struct tevent_req *subreq)
{
    struct tevent_req *req;

    req = tevent_req_callback_data(subreq, struct tevent_req);

    errno_t ret;
    dbus_uint16_t err_maj;
    dbus_uint32_t err_min;
    char *err_msg;

    ret = sss_dp_get_account_recv(req, subreq,
                                  &err_maj, &err_min,
                                  &err_msg);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE,
              "Unable to get information from Data Provider\n"
              "dp_error: [%u], errno: [%u], error_msg: [%s]\n",
              (unsigned int)err_maj, (unsigned int)err_min,
              err_msg ? err_msg : "none");
    }

    talloc_zfree(subreq);
    talloc_zfree(err_msg);
    /* Errors during individual lookups are ignored. */

    ret = pac_lookup_sids_next(req);
    if (ret == EOK) {
        tevent_req_done(req);
    } else if (ret != EAGAIN) {
        tevent_req_error(req, ret);
    }

    return;
}

static errno_t pac_lookup_sids_recv(struct tevent_req *req)
{
    TEVENT_REQ_RETURN_ON_ERROR(req);

    return EOK;
}

struct cli_protocol_version *register_cli_protocol_version(void)
{
    static struct cli_protocol_version pac_cli_protocol_version[] = {
        {1, "2011-04-12", "initial version"},
        {0, NULL, NULL}
    };

    return pac_cli_protocol_version;
}

static struct sss_cmd_table pac_cmds[] = {
    {SSS_GET_VERSION, sss_cmd_get_version},
    {SSS_PAC_ADD_PAC_USER, pac_add_pac_user},
    {SSS_CLI_NULL, NULL}
};

struct sss_cmd_table *get_pac_cmds(void) {
    return pac_cmds;
}
