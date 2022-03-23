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
                              const struct PAC_UPN_DNS_INFO *upn_dns_info)
{
    const char *delim;

    if (logon_info == NULL) {
        return ERR_CHECK_PAC_FAILED;
    }

    if (logon_info->info3.base.account_name.string == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing account name in PAC.\n");
        return ERR_CHECK_PAC_FAILED;
    }

    /* If upn_dns_info is not available we have nothing to check. */
    if (upn_dns_info == NULL) {
        DEBUG(SSSDBG_TRACE_ALL,
              "upn_dns_info buffer not present, nothing to check.\n");
        return EOK;
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
    if (upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED) {
        if (upn_dns_info->upn_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing UPN in PAC.\n");
            return ERR_CHECK_PAC_FAILED;
        }

        if (upn_dns_info->dns_domain_name == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing DNS domain name in PAC.\n");
            return ERR_CHECK_PAC_FAILED;
        }

        delim = strrchr(upn_dns_info->upn_name, '@');
        if (delim == NULL) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Missing '@' in UPN [%s] from PAC.\n",
                                       upn_dns_info->upn_name);
            return ERR_CHECK_PAC_FAILED;
        }

        if (strcasecmp(delim+1, upn_dns_info->dns_domain_name) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Domain part of UPN [%s] and "
                                       "DNS domain name [%s] do not match.\n",
                                       upn_dns_info->upn_name,
                                       upn_dns_info->dns_domain_name);
            return ERR_CHECK_PAC_FAILED;
        }

        if (strncasecmp(logon_info->info3.base.account_name.string,
                        upn_dns_info->upn_name,
                        (size_t) (delim - upn_dns_info->upn_name)) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "Name part of UPN [%s] and account name [%s] "
                  "do not match.\n", upn_dns_info->upn_name,
                  logon_info->info3.base.account_name.string);
            return ERR_CHECK_PAC_FAILED;
        }
    }

    /* The upn_dns_info is extended with the sAMAccountName and the SID of the
     * object. */
#ifdef HAVE_STRUCT_PAC_UPN_DNS_INFO_EX
    if (upn_dns_info->flags & PAC_UPN_DNS_FLAG_HAS_SAM_NAME_AND_SID) {
        if (strcasecmp(logon_info->info3.base.account_name.string,
                       upn_dns_info->ex.sam_name_and_sid.samaccountname) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE, "Account name in LOGON_INFO [%s] and "
                  "UPN_DNS_INFO [%s] PAC buffers do not match.\n",
                  logon_info->info3.base.account_name.string,
                  upn_dns_info->ex.sam_name_and_sid.samaccountname);
            return ERR_CHECK_PAC_FAILED;
        }

        if (!compare_sid_with_dom_sid_and_rid(
                                    upn_dns_info->ex.sam_name_and_sid.objectsid,
                                    logon_info->info3.base.domain_sid,
                                    logon_info->info3.base.rid)) {
            DEBUG(SSSDBG_CRIT_FAILURE, "SID from UPN_DNS_INFO PAC buffer "
                  "do not match data from LOGON_INFO buffer.\n");
            return ERR_CHECK_PAC_FAILED;
        }
    }
#else
    DEBUG(SSSDBG_TRACE_ALL,
          "This SSSD build does not support the sam_name_and_sid extension of "
          "the PAC_UPN_DNS_INFO buffer.\n");
#endif

    DEBUG(SSSDBG_TRACE_ALL, "PAC consistency check successful.\n");
    return EOK;
}

errno_t check_upn_from_user_and_pac(struct ldb_message *msg,
                                    struct PAC_UPN_DNS_INFO *upn_dns_info)
{
    const char *user_upn;

    if (upn_dns_info->upn_name == NULL) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Missing UPN in PAC.\n");
        return ERR_CHECK_PAC_FAILED;
    }

    user_upn = ldb_msg_find_attr_as_string(msg, SYSDB_UPN, NULL);

    /* If the user object doesn't have a UPN we would expect that the UPN in
     * the PAC_UPN_DNS_INFO buffer is generated and
     * PAC_UPN_DNS_FLAG_CONSTRUCTED is set. However, there might still be
     * configurations like 'ldap_user_principal = noSuchAttr' around. So we
     * just check and log a message. */
    if (user_upn == NULL
            && !(upn_dns_info->flags & PAC_UPN_DNS_FLAG_CONSTRUCTED)) {
        DEBUG(SSSDBG_MINOR_FAILURE, "User object does not have a UPN but PAC "
                  "says otherwise, maybe ldap_user_principal option is set.\n");
    }

    if (user_upn != NULL) {
        if (strcasecmp(user_upn, upn_dns_info->upn_name) != 0) {
            DEBUG(SSSDBG_CRIT_FAILURE,
                  "UPN of user entry and PAC do not match.\n");
            return ERR_CHECK_PAC_FAILED;
        }
    }

    DEBUG(SSSDBG_TRACE_ALL, "PAC UPN check successful.\n");
    return EOK;
}

errno_t ad_get_data_from_pac(TALLOC_CTX *mem_ctx,
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

    if (_logon_info != NULL) {
        *_logon_info = NULL;
    }
    if (_upn_dns_info != NULL) {
        *_upn_dns_info = NULL;
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

    if (_logon_info != NULL && *_logon_info == NULL) {
        ret = ERR_CHECK_PAC_FAILED;
        goto done;
    }

    /* Make sure the content of different PAC buffers is consistent. */
    if (_logon_info != NULL && _upn_dns_info != NULL) {
        ret = check_logon_info_upn_dns_info(*_logon_info, *_upn_dns_info);
        if (ret != EOK) {
            DEBUG(SSSDBG_OP_FAILURE, "Validating PAC data failed.\n");
            talloc_free(*_logon_info);
            *_logon_info = NULL;
            talloc_free(*_upn_dns_info);
            *_upn_dns_info = NULL;
            goto done;
        }
    }

    ret = EOK;

done:
    talloc_free(tmp_ctx);

    return ret;
}
