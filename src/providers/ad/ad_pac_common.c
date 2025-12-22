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


#include "providers/ad/ad_pac.h"
#include "util/util.h"

#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
static bool
compare_sid_with_dom_sid_and_rid(const struct dom_sid *sid,
                                 const struct dom_sid *dom,
                                 uint32_t rid)
{
    size_t c;

    if (sid == NULL || dom == NULL || rid == 0) {
        return false;
    }

    if (sid->sid_rev_num != dom->sid_rev_num) {
        return false;
    }

    for (c = 0; c < sizeof(sid->id_auth); c++) {
        if (sid->id_auth[c] != dom->id_auth[c]) {
            return false;
        }
    }

    if (sid->num_auths != dom->num_auths + 1) {
        return false;
    }

    for (c = 0; c < sid->num_auths; c++) {
        if (c == dom->num_auths) {
            if (sid->sub_auths[c] != rid) {
                return false;
            }
        } else {
            if (sid->sub_auths[c] != dom->sub_auths[c]) {
                return false;
            }
        }
    }

    return true;
}
#endif

static errno_t
check_logon_info_upn_dns_info(const struct PAC_LOGON_INFO *logon_info,
                              const struct PAC_UPN_DNS_INFO *upn_dns_info,
                              const uint32_t pac_check_opts)
{
    const char *delim;

    if (logon_info == NULL) {
        return ERR_CHECK_PAC_FAILED;
    }

    if (logon_info->info3.base.account_name.string == NULL) {
        DEBUG(SSSDBG_FUNC_DATA, "Missing account name in PAC.\n");
        return ERR_CHECK_PAC_FAILED;
    }

    /* If upn_dns_info is not available we have nothing to check. */
    if (upn_dns_info == NULL) {
        if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_PRESENT) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "UPN_DNS_INFO pac buffer required, but missing.\n");
            return ERR_CHECK_PAC_FAILED;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "upn_dns_info buffer not present, nothing to check.\n");
            return EOK;
        }
    }

    /* upn_dns_info has no information which is present in logon_info, so
     * nothing to check. */
    if (upn_dns_info->flags == 0) {
        DEBUG(SSSDBG_TRACE_ALL,
              "upn_dns_info buffer has no extra data to check.\n");
        return EOK;
    }

    /* The user object does not have userPrincipalName set explicitly and the
     * upn_name is constructed from the user name (sAMAccountName) and the DNS
     * domain name. Case-insensitive comparison will be used because AD handles
     * names case-insensitive. */
    if ((upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED)
                && (pac_check_opts & CHECK_PAC_CHECK_UPN)) {
        if (upn_dns_info->upn_name == NULL) {
            DEBUG(SSSDBG_FUNC_DATA, "Missing UPN in PAC.\n");
            return ERR_CHECK_PAC_FAILED;
        }

        if (upn_dns_info->dns_domain_name == NULL) {
            DEBUG(SSSDBG_FUNC_DATA, "Missing DNS domain name in PAC.\n");
            return ERR_CHECK_PAC_FAILED;
        }

        delim = strrchr(upn_dns_info->upn_name, '@');
        if (delim == NULL) {
            DEBUG(SSSDBG_FUNC_DATA, "Missing '@' in UPN [%s] from PAC.\n",
                                    upn_dns_info->upn_name);
            return ERR_CHECK_PAC_FAILED;
        }

        if (strcasecmp(delim+1, upn_dns_info->dns_domain_name) != 0) {
            DEBUG(SSSDBG_FUNC_DATA, "Domain part of UPN [%s] and "
                                    "DNS domain name [%s] do not match.\n",
                                    upn_dns_info->upn_name,
                                    upn_dns_info->dns_domain_name);
            return ERR_CHECK_PAC_FAILED;
        }

        if (strncasecmp(logon_info->info3.base.account_name.string,
                        upn_dns_info->upn_name,
                        (size_t) (delim - upn_dns_info->upn_name)) != 0) {
            DEBUG(SSSDBG_FUNC_DATA,
                  "Name part of UPN [%s] and account name [%s] "
                  "do not match.\n", upn_dns_info->upn_name,
                  logon_info->info3.base.account_name.string);
            return ERR_CHECK_PAC_FAILED;
        }
    }

    /* The upn_dns_info is extended with the sAMAccountName and the SID of the
     * object. */
#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
    if ((upn_dns_info->flags & PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID)
            && (pac_check_opts & CHECK_PAC_CHECK_UPN_DNS_INFO_EX)) {
        if (strcasecmp(logon_info->info3.base.account_name.string,
                       upn_dns_info->ex.sam_name_and_sid.samaccountname) != 0) {
            DEBUG(SSSDBG_FUNC_DATA, "Account name in LOGON_INFO [%s] and "
                  "UPN_DNS_INFO [%s] PAC buffers do not match.\n",
                  logon_info->info3.base.account_name.string,
                  upn_dns_info->ex.sam_name_and_sid.samaccountname);
            return ERR_CHECK_PAC_FAILED;
        }

        if (!compare_sid_with_dom_sid_and_rid(
                                    upn_dns_info->ex.sam_name_and_sid.objectsid,
                                    logon_info->info3.base.domain_sid,
                                    logon_info->info3.base.rid)) {
            DEBUG(SSSDBG_FUNC_DATA, "SID from UPN_DNS_INFO PAC buffer "
                  "do not match data from LOGON_INFO buffer.\n");
            return ERR_CHECK_PAC_FAILED;
        }
    }
#else
    DEBUG(SSSDBG_TRACE_ALL,
          "This SSSD build does not support the sam_name_and_sid extension of "
          "the UPN_DNS_INFO pac buffer.\n");
    if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT) {
        DEBUG(SSSDBG_FUNC_DATA,
              "UPN_DNS_INFO pac buffer extension required, but missing.\n");
        return ERR_CHECK_PAC_FAILED;
    }
#endif

    DEBUG(SSSDBG_TRACE_ALL, "PAC consistency check successful.\n");
    return EOK;
}

errno_t check_upn_and_sid_from_user_and_pac(struct ldb_message *msg,
                                          struct sss_idmap_ctx *idmap_ctx,
                                          struct PAC_UPN_DNS_INFO *upn_dns_info,
                                          const uint32_t pac_check_opts)
{
    const char *user_data;
    char *pac_ext_sid_str;
    enum idmap_error_code err;
    int cmp_ret;

    if (upn_dns_info == NULL || upn_dns_info->upn_name == NULL) {
        if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_PRESENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing UPN in PAC.\n");
            return ERR_CHECK_PAC_FAILED;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Missing UPN in PAC, but check is not required.\n");
            return EOK;
        }
    } else {
        user_data = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);

        /* If the user object doesn't have a UPN we would expect that the UPN in
         * the PAC_UPN_DNS_INFO buffer is generated and
         * PAC_UPN_DNS_FLAG_CONSTRUCTED is set. However, there might still be
         * configurations like 'ldap_user_principal = noSuchAttr' around. So we
         * just check and log a message. */
        if (user_data == NULL
                && !(upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED)) {
            DEBUG(SSSDBG_MINOR_FAILURE, "User object does not have a UPN but PAC "
                      "says otherwise, maybe ldap_user_principal option is set.\n");
            if (pac_check_opts & CHECK_PAC_CHECK_UPN) {
                if (pac_check_opts & CHECK_PAC_CHECK_UPN_ALLOW_MISSING) {
                    DEBUG(SSSDBG_IMPORTANT_INFO,
                          "UPN is missing but PAC UPN check required, "
                          "PAC validation failed. However, "
                          "'check_upn_allow_missing' is set and the error is "
                          "ignored. To make this message go away please check "
                          "why the UPN is not read from the server. In FreeIPA "
                          "environments 'ldap_user_principal' is most probably "
                          "set to a non-existing attribute name to avoid "
                          "issues with enterprise principals. This is not "
                          "needed anymore with recent versions of FreeIPA.\n");
                    sss_log(SSS_LOG_CRIT, "PAC validation issue, please check "
                                          "sssd_pac.log for details");
                    return EOK;
                } else {
                    DEBUG(SSSDBG_CRIT_FAILURE,
                          "UPN is missing but PAC UPN check required, "
                          "PAC validation failed.\n");
                    return ERR_CHECK_PAC_FAILED;
                }
            }
        }

        if (user_data != NULL) {
            if (strcasecmp(user_data, upn_dns_info->upn_name) != 0) {
                if (pac_check_opts & CHECK_PAC_CHECK_UPN) {
                    DEBUG(SSSDBG_CRIT_FAILURE, "UPN of user entry [%s] and "
                                               "PAC [%s] do not match.\n",
                                               user_data,
                                               upn_dns_info->upn_name);
                    return ERR_CHECK_PAC_FAILED;
                } else {
                    DEBUG(SSSDBG_IMPORTANT_INFO, "UPN of user entry [%s] and "
                                                 "PAC [%s] do not match, "
                                                 "ignored.\n", user_data,
                                                 upn_dns_info->upn_name);
                    return EOK;
                }
            }
        }

        DEBUG(SSSDBG_TRACE_ALL, "PAC UPN check successful.\n");
    }

#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
    if (upn_dns_info == NULL
           || !(upn_dns_info->flags & PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID) ) {
        if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing SID in PAC extension.\n");
            return ERR_CHECK_PAC_FAILED;
        } else {
            DEBUG(SSSDBG_TRACE_ALL,
                  "Missing SID in PAC extension, but check is not required.\n");
            return EOK;
        }
    } else {
        user_data = ldb_msg_find_attr_as_string(msg, SYSDB_SID_STR, NULL);
        if (user_data == NULL) {
            if (pac_check_opts & CHECK_PAC_CHECK_UPN_DNS_INFO_EX) {
                DEBUG(SSSDBG_CRIT_FAILURE,
                      "User has no SID stored but SID check is required.\n");
                return ERR_CHECK_PAC_FAILED;
            } else {
                DEBUG(SSSDBG_TRACE_ALL,
                      "User has no SID stored cannot check SID from PAC.\n");
                return EOK;
            }
        }

        err = sss_idmap_smb_sid_to_sid(idmap_ctx,
                                    upn_dns_info->ex.sam_name_and_sid.objectsid,
                                    &pac_ext_sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "Failed to convert SID from PAC externsion.\n");
            return EIO;
        }

        cmp_ret = strcmp(user_data, pac_ext_sid_str);
        err = sss_idmap_free_sid(idmap_ctx, pac_ext_sid_str);
        if (err != IDMAP_SUCCESS) {
            DEBUG(SSSDBG_OP_FAILURE,
                  "sss_idmap_free_sid() failed, ignored.\n");
        }
        if (cmp_ret != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "User SID [%s] and SID from PAC externsion [%s] differ.\n",
                  user_data, pac_ext_sid_str);
        }
    }
#else
    DEBUG(SSSDBG_TRACE_ALL,
          "This SSSD build does not support the sam_name_and_sid extension of "
          "the UPN_DNS_INFO pac buffer.\n");
    if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT) {
        DEBUG(SSSDBG_FUNC_DATA,
              "UPN_DNS_INFO pac buffer extension required, but missing.\n");
        return ERR_CHECK_PAC_FAILED;
    }
#endif

    return EOK;
}

errno_t ad_get_data_from_pac(TALLOC_CTX *mem_ctx, const uint32_t pac_check_opts,
                             uint8_t *pac_blob, size_t pac_len,
                             struct PAC_LOGON_INFO **_logon_info,
                             struct PAC_UPN_DNS_INFO **_upn_dns_info)
{
    DATA_BLOB blob;
    struct ndr_pull *ndr_pull;
    struct PAC_DATA *pac_data;
    enum ndr_err_code ndr_err;
    size_t c;
    int ret;
    TALLOC_CTX *tmp_ctx;

    if (_logon_info != NULL) {
        *_logon_info = NULL;
    }
    if (_upn_dns_info != NULL) {
        *_upn_dns_info = NULL;
    }

    tmp_ctx = talloc_new(NULL);
    if (tmp_ctx == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_new failed.\n");
        return ENOMEM;
    }

    blob.data = pac_blob;
    blob.length = pac_len;

    ndr_pull = ndr_pull_init_blob(&blob, tmp_ctx);
    if (ndr_pull == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_init_blob failed.\n");
        ret = ENOMEM;
        goto done;
    }
    ndr_pull->flags |= LIBNDR_FLAG_REF_ALLOC; /* FIXME: is this really needed ? */

    pac_data = talloc_zero(tmp_ctx, struct PAC_DATA);
    if (pac_data == NULL) {
        DEBUG(SSSDBG_OP_FAILURE, "talloc_zero failed.\n");
        ret = ENOMEM;
        goto done;
    }

    ndr_err = ndr_pull_PAC_DATA(ndr_pull, NDR_SCALARS|NDR_BUFFERS, pac_data);
    if (!NDR_ERR_CODE_IS_SUCCESS(ndr_err)) {
        DEBUG(SSSDBG_OP_FAILURE, "ndr_pull_PAC_DATA failed [%d]\n", ndr_err);
        ret =  EBADMSG;
        goto done;
    }

    for(c = 0; c < pac_data->num_buffers; c++) {
        switch (pac_data->buffers[c].type) {
        case PAC_TYPE_SRV_CHECKSUM:
            break;
        case PAC_TYPE_KDC_CHECKSUM:
            break;
        case PAC_TYPE_LOGON_INFO:
            if (_logon_info != NULL) {
                *_logon_info = talloc_steal(mem_ctx,
                                    pac_data->buffers[c].info->logon_info.info);
            }
            break;
        case PAC_TYPE_UPN_DNS_INFO:
            if (_upn_dns_info != NULL) {
                *_upn_dns_info = talloc_steal(mem_ctx,
                                      &pac_data->buffers[c].info->upn_dns_info);
            }
            break;
        default:
            DEBUG(SSSDBG_TRACE_ALL, "Unhandled PAC buffer type [%d].\n",
                                    pac_data->buffers[c].type);
        }
    }

    /* The logon_info buffer is the main PAC buffer for AD and FreeIPA users
     * with the basic user information, if this is missing we consider the PAC
     * as broken if PAC checking is not switched off. This is important
     * because new versions MIT Kerberos will add a PAC buffer as well, but
     * without an AD logon_info buffer. */
    if (pac_check_opts != 0) {
        if (_logon_info != NULL && *_logon_info == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "LOGON_INFO pac buffer missing.\n");
            ret = ERR_CHECK_PAC_FAILED;
            goto done;
        }
    }

    /* The upn_dns_info buffer was added with Windows 2008, so there might be
     * still very old installations which might not have it. But all relevant
     * Samba versions knows about it, so no ifdef-protection is needed. */
    if (_upn_dns_info != NULL && *_upn_dns_info == NULL
            && ((pac_check_opts & CHECK_PAC_UPN_DNS_INFO_PRESENT)
                    || (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT))) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "UPN_DNS_INFO pac buffer required, but missing.\n");
        ret = ERR_CHECK_PAC_FAILED;
        goto done;
    }

#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
    if (_upn_dns_info != NULL && *_upn_dns_info != NULL
            && !((*_upn_dns_info)->flags & PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID)
            && (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT)) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "UPN_DNS_INFO pac buffer extension required, but missing.\n");
        ret = ERR_CHECK_PAC_FAILED;
        goto done;
    }
#else
    DEBUG(SSSDBG_TRACE_ALL,
          "This SSSD build does not support the sam_name_and_sid extension of "
          "the UPN_DNS_INFO pac buffer.\n");
    if (pac_check_opts & CHECK_PAC_UPN_DNS_INFO_EX_PRESENT) {
        DEBUG(SSSDBG_FUNC_DATA,
              "UPN_DNS_INFO pac buffer extension required, but missing.\n");
        ret = ERR_CHECK_PAC_FAILED;
        goto done;
    }
#endif

    /* Make sure the content of different PAC buffers is consistent. */
    if (_logon_info != NULL && _upn_dns_info != NULL) {
        ret = check_logon_info_upn_dns_info(*_logon_info, *_upn_dns_info,
                                            pac_check_opts);
        if (ret != EOK) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Validating PAC data failed.\n");
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);
    if (ret != EOK) {
        if (_logon_info != NULL) {
            talloc_free(*_logon_info);
            *_logon_info = NULL;
        }
        if (_upn_dns_info != NULL) {
            talloc_free(*_upn_dns_info);
            *_upn_dns_info = NULL;
        }
    }

    return ret;
}
