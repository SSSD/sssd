/*
   SSSD

   PAC Responder - utility finctions

   Copyright (C) Sumit Bose <sbose@redhat.com> 2012

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
#include <stdbool.h>
#include <util/data_blob.h>
#include <gen_ndr/security.h>

#include "util/util.h"
#include "responder/pac/pacsrv.h"

static errno_t get_rid(struct dom_sid *sid, uint32_t *rid)
{
    if (sid == NULL || sid->num_auths < 1 || rid == NULL) {
        return EINVAL;
    }

    *rid = sid->sub_auths[sid->num_auths - 1];

    return EOK;
}

/**
 * Find the Posix ID to a SID from the local IPA domain
 */
errno_t local_sid_to_id(struct local_mapping_ranges *map, struct dom_sid *sid,
                        uint32_t *id)
{
    int ret;
    uint32_t rid;

    if (map == NULL || sid == NULL || id == NULL) {
        return EINVAL;
    }

    ret = get_rid(sid, &rid);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("get_rid failed.\n"));
        return ret;
    }

    if (rid >= map->primary_rids.min && rid <= map->primary_rids.max) {
        *id = map->local_ids.min + (rid -  map->primary_rids.min);
    } else if (rid >= map->secondary_rids.min &&
               rid <= map->secondary_rids.max) {
        *id = map->local_ids.min + (rid -  map->secondary_rids.min);
    } else {
        return ENOENT;
    }

    if (*id < map->local_ids.min || *id > map->local_ids.max) {
        return ERANGE;
    }

    return EOK;
}

/**
 * Add a new remote domain and the corresponding ID range to the context of
 * the libsss_idmap. Without this it is not possible to find the Posix UID for
 * a user fo the remote domain.
 */
errno_t add_idmap_domain(struct sss_idmap_ctx *idmap_ctx,
                         struct sysdb_ctx *sysdb,
                         const char *domain_name,
                         const char *dom_sid_str)
{
    struct sss_idmap_range range = {0, 0};
    enum idmap_error_code err;
    TALLOC_CTX *tmp_ctx = NULL;
    size_t range_count;
    struct range_info **range_list;
    size_t c;
    int ret;

    if (domain_name == NULL || dom_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing domain name or SID.\n"));
        return EINVAL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
        return ENOMEM;
    }

    ret = sysdb_get_ranges(tmp_ctx, sysdb, &range_count, &range_list);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, ("sysdb_get_ranges failed.\n"));
        goto done;
    }

    for (c = 0; c < range_count; c++) {
        if (range_list[c]->trusted_dom_sid != NULL &&
            strcmp(range_list[c]->trusted_dom_sid, dom_sid_str) == 0) {
                range.min = range_list[c]->base_id;
                range.max = range_list[c]->base_id +
                            range_list[c]->id_range_size - 1;
                /* TODO: add support for multiple ranges. */
            break;
        }
    }

    if (range.min == 0 && range.max == 0) {
        DEBUG(SSSDBG_OP_FAILURE, ("Failed to find mapping range for domain "
                                  "[%s][%s].\n", domain_name, dom_sid_str));
        ret = ENOENT;
        goto done;
    }

    err = sss_idmap_add_domain(idmap_ctx, domain_name, dom_sid_str, &range);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_idmap_add_domain failed.\n"));
        return EFAULT;
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    return ret;
}

/**
 * Find the corresponding UID for a user from a remote domain based on the
 * domain SID of the remote domain and the RID of the user.
 */
errno_t domsid_rid_to_uid(struct pac_ctx *pac_ctx,
                          struct sysdb_ctx *sysdb,
                          const char *domain_name,
                          struct dom_sid2 *domsid, uint32_t rid,
                          uid_t *uid)
{
    enum idmap_error_code err;
    char *sid_str = NULL;
    char *dom_sid_str = NULL;
    uint32_t id;
    int ret;

    err = sss_idmap_smb_sid_to_sid(pac_ctx->idmap_ctx, domsid,
                                   &dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_idmap_smb_sid_to_sid failed.\n"));
        ret = EFAULT;
        goto done;
    }

    sid_str = talloc_asprintf(NULL, "%s-%lu", dom_sid_str, (unsigned long) rid);
    if (sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("dom_sid_and_rid_string failed.\n"));
        return ENOMEM;
    }

    err = sss_idmap_smb_sid_to_sid(pac_ctx->idmap_ctx, domsid, &sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_idmap_smb_sid_to_sid failed.\n"));
        ret = EFAULT;
        goto done;
    }

    err = sss_idmap_sid_to_unix(pac_ctx->idmap_ctx, sid_str, &id);
    if (err == IDMAP_NO_DOMAIN) {
        ret = add_idmap_domain(pac_ctx->idmap_ctx, sysdb, domain_name,
                               dom_sid_str);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("add_idmap_domain failed.\n"));
            goto done;
        }

        err = sss_idmap_sid_to_unix(pac_ctx->idmap_ctx, sid_str, &id);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("sss_idmap_sid_to_unix failed "
                                         "even in the second attempt.\n"));
            ret = ENOENT;
            goto done;
        }
    } else if (err != IDMAP_SUCCESS && err != IDMAP_NO_DOMAIN) {
        DEBUG(SSSDBG_OP_FAILURE, ("sss_idmap_sid_to_unix failed.\n"));
        ret = EFAULT;
        goto done;
    }

    *uid = (uid_t) id;

    ret = EOK;

done:
    talloc_free(dom_sid_str);
    talloc_free(sid_str);
    return ret;
}

/**
 * Return information about the local domain from the main PAC responder
 * context or try to read it from cache and store it in the context.
 */
errno_t get_my_domain_data(struct pac_ctx *pac_ctx,
                           struct sss_domain_info *dom,
                           struct dom_sid **_sid,
                           struct local_mapping_ranges **_range_map)
{
    struct sysdb_ctx *sysdb;
    int ret;
    struct ldb_dn *basedn;
    const char *attrs[] = {SYSDB_SUBDOMAIN_ID,
                           NULL};
    size_t msgs_count;
    const char *sid_str;
    struct ldb_message **msgs;
    TALLOC_CTX *tmp_ctx = NULL;
    struct dom_sid *sid = NULL;
    char *dom_name;
    enum idmap_error_code err;
    size_t range_count;
    struct range_info **range_list;
    struct local_mapping_ranges *r_map = NULL;
    size_t c;

    if (pac_ctx->my_dom_sid == NULL || pac_ctx->range_map == NULL) {
        if (dom->parent != NULL) {
            sysdb = dom->parent->sysdb;
            dom_name = dom->parent->name;
        } else {
            sysdb = dom->sysdb;
            dom_name = dom->name;
        }

        if (sysdb == NULL) {
            DEBUG(SSSDBG_FATAL_FAILURE, ("Missing sysdb context.\n"));
            ret = EINVAL;
            goto done;
        }

        tmp_ctx = talloc_new(NULL);
        if (tmp_ctx == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_new failed.\n"));
            ret = ENOMEM;
            goto done;
        }

        basedn = sysdb_domain_dn(sysdb, tmp_ctx, dom_name);
        if (basedn == NULL) {
            ret = ENOMEM;
            goto done;
        }

        if (pac_ctx->my_dom_sid == NULL) {
            ret = sysdb_search_entry(tmp_ctx, sysdb, basedn, LDB_SCOPE_BASE, NULL,
                                     attrs, &msgs_count, &msgs);
            if (ret != LDB_SUCCESS) {
                ret = EIO;
                goto done;
            }

            if (msgs_count != 1) {
                DEBUG(SSSDBG_OP_FAILURE, ("Base search returned [%d] results, "
                                         "expected 1.\n", msgs_count));
                ret = EINVAL;
                goto done;
            }

            sid_str = ldb_msg_find_attr_as_string(msgs[0], SYSDB_SUBDOMAIN_ID, NULL);
            if (sid_str == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("SID of my domain is not available.\n"));
                ret = EINVAL;
                goto done;
            }

            err = sss_idmap_sid_to_smb_sid(pac_ctx->idmap_ctx, sid_str, &sid);
            if (err != IDMAP_SUCCESS) {
                DEBUG(SSSDBG_OP_FAILURE, ("sss_idmap_sid_to_smb_sid failed.\n"));
                ret = EFAULT;
                goto done;
            }

            pac_ctx->my_dom_sid = talloc_memdup(pac_ctx, sid,
                                                sizeof(struct dom_sid));
            if (pac_ctx->my_dom_sid == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("talloc_memdup failed.\n"));
                ret = ENOMEM;
                goto done;
            }
        }

        if (pac_ctx->range_map == NULL) {
            ret = sysdb_get_ranges(tmp_ctx, sysdb, &range_count, &range_list);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("sysdb_get_ranges failed.\n"));
                goto done;
            }

            for (c = 0; c < range_count; c++) {
                if (range_list[c]->trusted_dom_sid == NULL &&
                    range_list[c]->secondary_base_rid != 0) {
                        r_map = talloc_zero(pac_ctx,
                                            struct local_mapping_ranges);
                        if (r_map == NULL) {
                            DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
                            ret = ENOMEM;
                            goto done;
                        }

                        r_map->local_ids.min = range_list[c]->base_id;
                        r_map->local_ids.max = range_list[c]->base_id +
                                                   range_list[c]->id_range_size - 1;

                        r_map->primary_rids.min = range_list[c]->base_rid;
                        r_map->primary_rids.max = range_list[c]->base_rid +
                                                  range_list[c]->id_range_size - 1;

                        r_map->secondary_rids.min = range_list[c]->secondary_base_rid;
                        r_map->secondary_rids.max = range_list[c]->secondary_base_rid +
                                                    range_list[c]->id_range_size - 1;

                        /* TODO: add support for multiple ranges. */
                        break;
                }
            }

            if (r_map == NULL) {
                DEBUG(SSSDBG_OP_FAILURE, ("Failed to find local id map.\n"));
                ret = ENOENT;
                goto done;
            }

            pac_ctx->range_map = r_map;
         }

    }

    *_sid = pac_ctx->my_dom_sid;
    *_range_map = pac_ctx->range_map;

    ret = EOK;

done:
    talloc_free(sid);
    talloc_free(tmp_ctx);

    return ret;
}

/**
 * Check if a given SID belongs to a domain identified by the domain SID.
 */
bool dom_sid_in_domain(const struct dom_sid *domain_sid,
                       const struct dom_sid *sid)
{
    size_t c;

    if (!domain_sid || !sid) {
        return false;
    }

    if (domain_sid->sid_rev_num != sid->sid_rev_num) {
        return false;
    }

    for (c = 0; c < 6; c++) {
        if (domain_sid->id_auth[c] != sid->id_auth[c]) {
            return false;
        }
    }

    if (domain_sid->num_auths > sid->num_auths) {
        return false;
    }

    for (c = 0; c < domain_sid->num_auths-1; c++) {
        if (domain_sid->sub_auths[c] != sid->sub_auths[c]) {
            return false;
        }
    }

    return true;
}

/**
 * Find all Posix GIDs from a PAC by searching for group SIDs from the local
 * domain and convert them to GIDs.
 */
errno_t get_gids_from_pac(TALLOC_CTX *mem_ctx,
                          struct local_mapping_ranges *range_map,
                          struct dom_sid *domain_sid,
                          struct PAC_LOGON_INFO *logon_info,
                          size_t *_gid_count, gid_t **_gids)
{
    int ret;
    size_t g = 0;
    size_t s;
    struct netr_SamInfo3 *info3;
    gid_t *gids = NULL;

    info3 = &logon_info->info3;

    if (info3->sidcount == 0) {
        DEBUG(SSSDBG_TRACE_ALL, ("No extra groups found.\n"));
        ret = EOK;
        goto done;
    }

    gids = talloc_array(mem_ctx, gid_t, info3->sidcount);
    if (gids == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_array failed.\n"));
        ret = ENOMEM;
        goto done;
    }

    for(s = 0; s < info3->sidcount; s++) {
        if (dom_sid_in_domain(domain_sid, info3->sids[s].sid)) {
            ret = local_sid_to_id(range_map, info3->sids[s].sid, &gids[g]);
            if (ret != EOK) {
                DEBUG(SSSDBG_OP_FAILURE, ("get_rid failed.\n"));
                goto done;
            }
            DEBUG(SSSDBG_TRACE_ALL, ("Found extra group "
                                     "with gid [%d].\n", gids[g]));
            g++;
        }
    }

    ret = EOK;

done:
    if (ret == EOK) {
        *_gid_count = g;
        *_gids = gids;
    } else {
        talloc_free(gids);
    }

    return ret;
}

/**
 * Extract the PAC logon data from an NDR blob.
 */
errno_t get_data_from_pac(TALLOC_CTX *mem_ctx,
                          uint8_t *pac_blob, size_t pac_len,
                          struct PAC_LOGON_INFO **_logon_info)
{
    DATA_BLOB blob;
    struct ndr_pull *ndr_pull;
    struct PAC_DATA *pac_data;
    enum ndr_err_code ndr_err;
    size_t c;
    int ret;

    blob.data = pac_blob;
    blob.length = pac_len;

    ndr_pull = ndr_pull_init_blob(&blob, mem_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("ndr_pull_init_blob failed.\n"));
        return ENOMEM;
    }
    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC; /* FIXME: is this really needed ? */

    pac_data = talloc_zero(mem_ctx, struct PAC_DATA);
    if (pac_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    ndr_err = ndr_pull_PAC_DATA(ndr_pull, NDR_SCALARS|NDR_BUFFERS, pac_data);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, ("ndr_pull_PAC_DATA failed [%d]\n", ndr_err));
        return EBADMSG;
    }

    for(c = 0; c < pac_data->num_buffers; c++) {
        if (pac_data->buffers[c].type == PAC_TYPE_LOGON_INFO) {
            *_logon_info = pac_data->buffers[c].info->logon_info.info;

            return EOK;
        }
    }

    ret = EINVAL;

    talloc_free(pac_data);
    return ret;
}

/**
 * Fill up the passwd struct with data from the PAC logon info
 */
errno_t get_pwd_from_pac(TALLOC_CTX *mem_ctx,
                         struct pac_ctx *pac_ctx,
                         struct sss_domain_info *dom,
                         struct PAC_LOGON_INFO *logon_info,
                         struct passwd **_pwd)
{
    struct passwd *pwd = NULL;
    struct netr_SamBaseInfo *base_info;
    int ret;

    pwd = talloc_zero(mem_ctx, struct passwd);
    if (pwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, ("talloc_zero failed.\n"));
        return ENOMEM;
    }

    base_info = &logon_info->info3.base;

    if (base_info->account_name.size != 0) {
        pwd->pw_name = talloc_strdup(pwd,
                                     base_info->account_name.string);
        if (pwd->pw_name == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing account name in PAC.\n"));
        ret = EINVAL;
        goto done;
    }

    if (base_info->rid > 0) {
        ret = domsid_rid_to_uid(pac_ctx, dom->sysdb, dom->name,
                                base_info->domain_sid,
                                base_info->rid, &pwd->pw_uid);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, ("domsid_rid_to_uid failed.\n"));
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing user RID in PAC.\n"));
        ret = EINVAL;
        goto done;
    }

    pwd->pw_gid = 0; /* We use MPGs for sub-domains */

    if (base_info->full_name.size != 0) {
        pwd->pw_gecos = talloc_strdup(pwd, base_info->full_name.string);
        if (pwd->pw_gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, ("talloc_strdup failed.\n"));
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE, ("Missing full name in PAC, "
                                  "gecos field will by empty.\n "));
    }

    if (dom->subdomain_homedir) {
        pwd->pw_dir = expand_homedir_template(pwd, dom->subdomain_homedir,
                                              pwd->pw_name, pwd->pw_uid,
                                              dom->name);
        if (pwd->pw_dir == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    pwd->pw_shell = NULL; /* Using default */

    *_pwd = pwd;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(pwd);
    }

    return ret;
}
