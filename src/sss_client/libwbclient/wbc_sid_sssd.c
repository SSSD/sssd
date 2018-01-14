/*
   UNIX SMB/CIFS implementation.

   Winbind client API - SSSD version

   Copyright (C) Sumit Bose <sbose@redhat.com> 2014

   This library is free software; you can redistribute it and/or
   modify it under the terms of the GNU Lesser General Public
   License as published by the Free Software Foundation; either
   version 3 of the License, or (at your option) any later version.

   This library is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
   Library General Public License for more details.

   You should have received a copy of the GNU Lesser General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

/* Required Headers */
#include "config.h"

#include <stdio.h>

#include <errno.h>

#include "sss_client/idmap/sss_nss_idmap.h"

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

#define MAX_NAME_LEN 1024

static int sss_id_type_to_wbcSidType(enum sss_id_type sss_type,
                                     enum wbcSidType *name_type)
{
    switch (sss_type) {
    case SSS_ID_TYPE_NOT_SPECIFIED:
        *name_type = WBC_SID_NAME_USE_NONE;
        break;
    case SSS_ID_TYPE_UID:
    case SSS_ID_TYPE_BOTH:
        *name_type = WBC_SID_NAME_USER;
        break;
    case SSS_ID_TYPE_GID:
        *name_type = WBC_SID_NAME_DOM_GRP;
        break;
    default:
        return EINVAL;
    }

    return 0;
};

/* Convert a domain and name to SID */
wbcErr wbcLookupName(const char *domain,
             const char *name,
             struct wbcDomainSid *sid,
             enum wbcSidType *name_type)
{
    char *fq_name = NULL;
    char *str_sid;
    enum sss_id_type type;
    int ret;
    wbcErr wbc_status;

    if (domain == NULL || name == NULL
            || strnlen(domain, MAX_NAME_LEN) == MAX_NAME_LEN
            || strnlen(name, MAX_NAME_LEN) == MAX_NAME_LEN) {
        return WBC_ERR_INVALID_PARAM;
    }
    ret = asprintf(&fq_name, "%s@%s", name, domain);
    if (ret == -1) {
        return WBC_ERR_NO_MEMORY;
    }

    ret = sss_nss_getsidbyname(fq_name, &str_sid, &type);
    free(fq_name);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    ret = sss_id_type_to_wbcSidType(type, name_type);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    wbc_status = wbcStringToSid(str_sid, sid);
    free(str_sid);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    return WBC_ERR_SUCCESS;
}


/* Convert a SID to a domain and name */
wbcErr wbcLookupSid(const struct wbcDomainSid *sid,
                    char **pdomain,
                    char **pname,
                    enum wbcSidType *pname_type)
{
    char *str_sid;
    char *fq_name = NULL;
    enum sss_id_type type;
    int ret;
    char *p;
    wbcErr wbc_status;

    wbc_status = wbcSidToString(sid, &str_sid);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    ret = sss_nss_getnamebysid(str_sid, &fq_name, &type);
    wbcFreeMemory(str_sid);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    if (pname_type != NULL) {
        ret = sss_id_type_to_wbcSidType(type, pname_type);
        if (ret != 0) {
            wbc_status = WBC_ERR_UNKNOWN_FAILURE;
            goto done;
        }
    }

    /* TODO: it would be nice to have an sss_nss_getnamebysid() call which
    * returns name and domain separately. */
    p = strchr(fq_name, '@');
    if (p == NULL) {
        wbc_status = WBC_ERR_UNKNOWN_FAILURE;
        goto done;
    }

    *p = '\0';
    if (pname != NULL) {
        *pname = wbcStrDup(fq_name);
        if (*pname == NULL) {
            wbc_status = WBC_ERR_NO_MEMORY;
            goto done;
        }
    }

    if (pdomain != NULL) {
        *pdomain = wbcStrDup(p + 1);
        if (*pdomain == NULL) {
            wbcFreeMemory(*pname);
            wbc_status = WBC_ERR_NO_MEMORY;
            goto done;
        }
    }

    wbc_status = WBC_ERR_SUCCESS;
done:
    free(fq_name);
    return wbc_status;
}

wbcErr wbcLookupSids(const struct wbcDomainSid *sids, int num_sids,
             struct wbcDomainInfo **pdomains, int *pnum_domains,
             struct wbcTranslatedName **pnames)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Translate a collection of RIDs within a domain to names */

wbcErr wbcLookupRids(struct wbcDomainSid *dom_sid,
             int num_rids,
             uint32_t *rids,
             const char **pp_domain_name,
             const char ***pnames,
             enum wbcSidType **ptypes)
{
    struct wbcDomainSid obj_sid = {0};
    size_t c;
    wbcErr err;
    char *domain;
    char *name;
    enum wbcSidType type;
    const char **names = NULL;
    enum wbcSidType *types = NULL;

    obj_sid.sid_rev_num = dom_sid->sid_rev_num;
    obj_sid.num_auths = dom_sid->num_auths + 1;
    for (c = 0; c < 6; c++) {
        obj_sid.id_auth[c] = dom_sid->id_auth[c];
    }
    for (c = 0; c < WBC_MAXSUBAUTHS; c++) {
        obj_sid.sub_auths[c] = dom_sid->sub_auths[c];
    }

    names = wbcAllocateStringArray(num_rids + 1);
    if (names == NULL) {
        err = WBC_ERR_NO_MEMORY;
        goto done;
    }

    types = wbcAllocateMemory(num_rids + 1, sizeof(enum wbcSidType), NULL);
    if (types == NULL) {
        err = WBC_ERR_NO_MEMORY;
        goto done;
    }

    for (c = 0; c < num_rids; c++) {
        obj_sid.sub_auths[obj_sid.num_auths - 1] = rids[c];

        err = wbcLookupSid(&obj_sid, &domain, &name, &type);
        if (err != WBC_ERR_SUCCESS) {
            goto done;
        }

        names[c] = strdup(name);
        wbcFreeMemory(name);
        if (names[c] == NULL) {
            err = WBC_ERR_NO_MEMORY;
            goto done;
        }
        types[c] = type;

        if (c == 0) {
            *pp_domain_name = domain;
        } else {
            wbcFreeMemory(domain);
        }
    }

    *pnames = names;
    *ptypes = types;

    err = WBC_ERR_SUCCESS;

done:
    if (err != WBC_ERR_SUCCESS) {
        wbcFreeMemory(types);
        wbcFreeMemory(names);
    }

    return err;
}

/* Get the groups a user belongs to */
wbcErr wbcLookupUserSids(const struct wbcDomainSid *user_sid,
             bool domain_groups_only,
             uint32_t *num_sids,
             struct wbcDomainSid **_sids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Get alias membership for sids */
wbcErr wbcGetSidAliases(const struct wbcDomainSid *dom_sid,
            struct wbcDomainSid *sids,
            uint32_t num_sids,
            uint32_t **alias_rids,
            uint32_t *num_alias_rids)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}


/* Lists Users */
wbcErr wbcListUsers(const char *domain_name,
            uint32_t *_num_users,
            const char ***_users)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Lists Groups */
wbcErr wbcListGroups(const char *domain_name,
             uint32_t *_num_groups,
             const char ***_groups)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}

wbcErr wbcGetDisplayName(const struct wbcDomainSid *sid,
             char **pdomain,
             char **pfullname,
             enum wbcSidType *pname_type)
{
    WBC_SSSD_NOT_IMPLEMENTED;
}
