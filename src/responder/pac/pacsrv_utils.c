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
#include <sys/types.h>
#include <stdbool.h>
#include <util/data_blob.h>
#include <gen_ndr/security.h>

#include "util/util.h"
#include "responder/pac/pacsrv.h"

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

errno_t get_sids_from_pac(TALLOC_CTX *mem_ctx,
                          struct pac_ctx *pac_ctx,
                          struct PAC_LOGON_INFO *logon_info,
                          char **_user_sid_str,
                          char **_primary_group_sid_str,
                          hash_table_t **_sid_table)
{
    int ret;
    size_t s;
    struct netr_SamInfo3 *info3;
    struct sss_domain_info *user_dom;
    struct sss_domain_info *group_dom;
    char *sid_str = NULL;
    char *msid_str = NULL;
    char *user_dom_sid_str = NULL;
    size_t user_dom_sid_str_len;
    enum idmap_error_code err;
    hash_table_t *sid_table = NULL;
    hash_key_t key;
    hash_value_t value;
    char *rid_start;
    struct ldb_result *msg = NULL;
    char *user_sid_str = NULL;
    char *primary_group_sid_str = NULL;

    if (pac_ctx == NULL || logon_info == NULL || _sid_table == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing parameter.\n");
        return EINVAL;
    }

    info3 = &logon_info->info3;

    ret = sss_hash_create(mem_ctx,
                          info3->sidcount + info3->base.groups.count + 2,
                          &sid_table);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_hash_create failed.\n");
        goto done;
    }

    key.type = HASH_KEY_STRING;
    value.type = HASH_VALUE_ULONG;

    err = sss_idmap_smb_sid_to_sid(pac_ctx->idmap_ctx, info3->base.domain_sid,
                                   &user_dom_sid_str);
    if (err != IDMAP_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
        ret = EFAULT;
        goto done;
    }

    ret = responder_get_domain_by_id(pac_ctx->rctx, user_dom_sid_str,
                                     &user_dom);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "responder_get_domain_by_id failed.\n");
        ret = EINVAL;
        goto done;
    }

    user_dom_sid_str_len = strlen(user_dom_sid_str);
    sid_str = talloc_zero_size(mem_ctx, user_dom_sid_str_len + 12);
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

    user_sid_str = talloc_strdup(mem_ctx, sid_str);
    if (user_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key.str = sid_str;
    value.ul = 0;

    ret = sysdb_search_object_by_sid(mem_ctx, user_dom, sid_str, NULL, &msg);
    if (ret == EOK && msg->count == 1) {
        value.ul = ldb_msg_find_attr_as_uint64(msg->msgs[0], SYSDB_UIDNUM, 0);
    }
    talloc_zfree(msg);

    ret = hash_enter(sid_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                  ret, hash_error_string(ret));
        ret = EIO;
        goto done;
    }


    memset(rid_start, '\0', 12);
    ret = snprintf(rid_start, 12, "-%lu",
                                  (unsigned long) info3->base.primary_gid);
    if (ret < 0 || ret > 12) {
        DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
        ret = EIO;
        goto done;
    }

    primary_group_sid_str = talloc_strdup(mem_ctx, sid_str);
    if (primary_group_sid_str == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key.str = sid_str;
    value.ul = 0;

    ret = sysdb_search_object_by_sid(mem_ctx, user_dom, sid_str, NULL, &msg);
    if (ret == EOK && msg->count == 1) {
        value.ul = ldb_msg_find_attr_as_uint64(msg->msgs[0], SYSDB_GIDNUM, 0);
    }
    talloc_zfree(msg);

    ret = hash_enter(sid_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                  ret, hash_error_string(ret));
        ret = EIO;
        goto done;
    }


    for (s = 0; s < info3->base.groups.count; s++) {
        memset(rid_start, '\0', 12);
        ret = snprintf(rid_start, 12, "-%lu",
                                (unsigned long) info3->base.groups.rids[s].rid);
        if (ret < 0 || ret > 12) {
            DEBUG(SSSDBG_OP_FAILURE, "snprintf failed.\n");
            ret = EIO;
            goto done;
        }

        key.str = sid_str;
        value.ul = 0;

        ret = sysdb_search_object_by_sid(mem_ctx, user_dom, sid_str,
                                         NULL, &msg);
        if (ret == EOK && msg->count == 1) {
            value.ul = ldb_msg_find_attr_as_uint64(msg->msgs[0],
                                                   SYSDB_GIDNUM, 0);
        }
        talloc_zfree(msg);

        ret = hash_enter(sid_table, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                      ret, hash_error_string(ret));
            ret = EIO;
            goto done;
        }

    }

    for(s = 0; s < info3->sidcount; s++) {
        err = sss_idmap_smb_sid_to_sid(pac_ctx->idmap_ctx, info3->sids[s].sid,
                                       &msid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "sss_idmap_smb_sid_to_sid failed.\n");
            ret = EFAULT;
            goto done;
        }

        key.str = msid_str;
        value.ul = 0;

        ret = responder_get_domain_by_id(pac_ctx->rctx, msid_str, &group_dom);
        if (ret == EOK) {
            ret = sysdb_search_object_by_sid(mem_ctx, group_dom, msid_str,
                                             NULL, &msg);
            if (ret == EOK && msg->count == 1 ) {
                value.ul = ldb_msg_find_attr_as_uint64(msg->msgs[0],
                                                       SYSDB_GIDNUM, 0);
            }
            talloc_zfree(msg);
        }

        ret = hash_enter(sid_table, &key, &value);
        sss_idmap_free_sid(pac_ctx->idmap_ctx, msid_str);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "hash_enter failed [%d][%s].\n",
                                      ret, hash_error_string(ret));
            ret = EIO;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(sid_str);
    sss_idmap_free_sid(pac_ctx->idmap_ctx, user_dom_sid_str);

    if (ret == EOK) {
        *_sid_table = sid_table;
        *_user_sid_str = user_sid_str;
        *_primary_group_sid_str = primary_group_sid_str;
    } else {
        hash_destroy(sid_table);
        talloc_free(user_sid_str);
        talloc_free(primary_group_sid_str);
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
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_init_blob failed.\n");
        return ENOMEM;
    }
    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC; /* FIXME: is this really needed ? */

    pac_data = talloc_zero(mem_ctx, struct PAC_DATA);
    if (pac_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    ndr_err = ndr_pull_PAC_DATA(ndr_pull, NDR_SCALARS|NDR_BUFFERS, pac_data);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_PAC_DATA failed [%d]\n", ndr_err);
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
                         struct sss_domain_info *dom,
                         char *user_sid_str,
                         char *primary_group_sid_str,
                         hash_table_t *sid_table,
                         struct PAC_LOGON_INFO *logon_info,
                         struct passwd **_pwd,
                         struct sysdb_attrs **_attrs)
{
    struct passwd *pwd = NULL;
    struct sysdb_attrs *attrs = NULL;
    struct netr_SamBaseInfo *base_info;
    int ret;
    char *lname;
    char *uc_realm;
    char *upn;
    hash_key_t key;
    hash_value_t value;
    struct sss_nss_homedir_ctx homedir_ctx;

    pwd = talloc_zero(mem_ctx, struct passwd);
    if (pwd == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        return ENOMEM;
    }

    base_info = &logon_info->info3.base;

    if (base_info->account_name.size == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing account name in PAC.\n");
        ret = EINVAL;
        goto done;
    }
    if (base_info->rid == 0) {
        DEBUG(SSSDBG_OP_FAILURE, "Missing user RID in PAC.\n");
        ret = EINVAL;
        goto done;
    }

    /* To be compatible with winbind based lookups we have to use lower
     * case names only, effectively making the domain case-insenvitive. */
    lname = sss_tc_utf8_str_tolower(pwd, base_info->account_name.string);
    if (lname == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sss_tc_utf8_str_tolower failed.\n");
        ret = ENOMEM;
        goto done;
    }

    /* Subdomain use fully qualified names */
    pwd->pw_name = sss_get_domain_name(pwd, lname, dom);
    if (!pwd->pw_name) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_sprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    key.type = HASH_KEY_STRING;
    key.str = user_sid_str;
    ret = hash_lookup(sid_table, &key, &value);
    if (ret != HASH_SUCCESS) {
        DEBUG(SSSDBG_OP_FAILURE, "hash_lookup failed.\n");
        ret = EIO;
        goto done;
    }
    if (value.type != HASH_VALUE_ULONG) {
        DEBUG(SSSDBG_OP_FAILURE, "Wrong value type.\n");
        ret = EIO;
        goto done;
    }
    pwd->pw_uid = value.ul;

    if (IS_SUBDOMAIN(dom) || dom->mpg) {
        pwd->pw_gid = 0; /* We use MPGs for sub-domains */
    } else {
        key.type = HASH_KEY_STRING;
        key.str = primary_group_sid_str;
        ret = hash_lookup(sid_table, &key, &value);
        if (ret != HASH_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE, "hash_lookup failed.\n");
            ret = EIO;
            goto done;
        }
        if (value.type != HASH_VALUE_ULONG) {
            DEBUG(SSSDBG_OP_FAILURE, "Wrong value type.\n");
            ret = EIO;
            goto done;
        }
        pwd->pw_gid = value.ul;
    }

    if (base_info->full_name.size != 0) {
        pwd->pw_gecos = talloc_strdup(pwd, base_info->full_name.string);
        if (pwd->pw_gecos == NULL) {
            DEBUG(SSSDBG_OP_FAILURE, "talloc_strdup failed.\n");
            ret = ENOMEM;
            goto done;
        }
    } else {
        DEBUG(SSSDBG_OP_FAILURE, "Missing full name in PAC, "
                                  "gecos field will by empty.\n ");
    }

    /* Check if there is a special homedir template for sub-domains. If not a
     * fallback will be added by the NSS responder. */
    if (IS_SUBDOMAIN(dom) && dom->subdomain_homedir) {
        ZERO_STRUCT(homedir_ctx);

        homedir_ctx.username = lname;
        homedir_ctx.uid = pwd->pw_uid;
        homedir_ctx.domain = dom->name;
        homedir_ctx.flatname = dom->flat_name;
        homedir_ctx.config_homedir_substr = dom->homedir_substr;

        pwd->pw_dir = expand_homedir_template(pwd, dom->subdomain_homedir,
                                              &homedir_ctx);
        if (pwd->pw_dir == NULL) {
            ret = ENOMEM;
            goto done;
        }
    }

    pwd->pw_shell = NULL; /* Using default */

    attrs = sysdb_new_attrs(mem_ctx);
    if (attrs == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_new_attrs failed.\n");
        ret = ENOMEM;
        goto done;
    }

    uc_realm = get_uppercase_realm(mem_ctx, dom->name);
    if (uc_realm == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "get_uppercase_realm failed.\n");
        ret = ENOMEM;
        goto done;
    }

    upn = talloc_asprintf(mem_ctx, "%s@%s", lname, uc_realm);
    talloc_free(uc_realm);
    if (upn == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_asprintf failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_UPN, upn);
    talloc_free(upn);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
        goto done;
    }

    ret = sysdb_attrs_add_lc_name_alias(attrs, pwd->pw_name);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_lc_name_alias failed.\n");
        goto done;
    }

    ret = sysdb_attrs_add_string(attrs, SYSDB_SID_STR, user_sid_str);
    if (ret != EOK) {
        DEBUG(SSSDBG_OP_FAILURE, "sysdb_attrs_add_string failed.\n");
        goto done;
    }

    *_pwd = pwd;
    *_attrs = attrs;

    ret = EOK;

done:
    if (ret != EOK) {
        talloc_free(pwd);
    }

    return ret;
}
