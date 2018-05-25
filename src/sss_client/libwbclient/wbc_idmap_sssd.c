/*
   Unix SMB/CIFS implementation.

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

#include "sss_client/idmap/sss_nss_idmap.h"

#include "libwbclient.h"
#include "wbc_sssd_internal.h"

/* Convert a Windows SID to a Unix uid, allocating an uid if needed */
wbcErr wbcSidToUid(const struct wbcDomainSid *sid, uid_t *puid)
{
    int ret;
    char *sid_str;
    uint32_t id;
    enum sss_id_type type;
    wbcErr wbc_status;

    wbc_status = wbcSidToString(sid, &sid_str);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    ret = sss_nss_getidbysid(sid_str, &id, &type);
    wbcFreeMemory(sid_str);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    if (type != SSS_ID_TYPE_UID && type != SSS_ID_TYPE_BOTH) {
        return WBC_ERR_UNKNOWN_GROUP;
    }

    *puid = (uid_t) id;

    return WBC_ERR_SUCCESS;
}

/* Convert a Unix uid to a Windows SID, allocating a SID if needed */
wbcErr wbcUidToSid(uid_t uid, struct wbcDomainSid *sid)
{
    int ret;
    char *str_sid;
    enum sss_id_type type;
    wbcErr wbc_status;

    ret = sss_nss_getsidbyuid(uid, &str_sid, &type);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    if (type != SSS_ID_TYPE_UID && type != SSS_ID_TYPE_BOTH) {
        free(str_sid);
        return WBC_ERR_UNKNOWN_USER;
    }

    wbc_status = wbcStringToSid(str_sid, sid);
    free(str_sid);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    return WBC_ERR_SUCCESS;
}

/** @brief Convert a Windows SID to a Unix gid, allocating a gid if needed
 *
 * @param *sid        Pointer to the domain SID to be resolved
 * @param *pgid       Pointer to the resolved gid_t value
 *
 * @return #wbcErr
 *
 **/

wbcErr wbcSidToGid(const struct wbcDomainSid *sid, gid_t *pgid)
{
    int ret;
    char *sid_str;
    uint32_t id;
    enum sss_id_type type;
    wbcErr wbc_status;

    wbc_status = wbcSidToString(sid, &sid_str);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    ret = sss_nss_getidbysid(sid_str, &id, &type);
    wbcFreeMemory(sid_str);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    if (type != SSS_ID_TYPE_GID && type != SSS_ID_TYPE_BOTH) {
        return WBC_ERR_UNKNOWN_GROUP;
    }

    *pgid = (gid_t) id;

    return WBC_ERR_SUCCESS;
}

/* Convert a Unix gid to a Windows SID, allocating a SID if needed */
wbcErr wbcGidToSid(gid_t gid, struct wbcDomainSid *sid)
{
    int ret;
    char *str_sid;
    enum sss_id_type type;
    wbcErr wbc_status;

    ret = sss_nss_getsidbygid(gid, &str_sid, &type);
    if (ret != 0) {
        return WBC_ERR_UNKNOWN_FAILURE;
    }

    if (type != SSS_ID_TYPE_GID && type != SSS_ID_TYPE_BOTH) {
        free(str_sid);
        return WBC_ERR_UNKNOWN_USER;
    }

    wbc_status = wbcStringToSid(str_sid, sid);
    free(str_sid);
    if (!WBC_ERROR_IS_OK(wbc_status)) {
        return wbc_status;
    }

    return WBC_ERR_SUCCESS;
}

/* Obtain a new uid from Winbind */
wbcErr wbcAllocateUid(uid_t *puid)
{
    /* Not supported by SSSD */
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Obtain a new gid from Winbind */
wbcErr wbcAllocateGid(gid_t *pgid)
{
    /* Not supported by SSSD */
    WBC_SSSD_NOT_IMPLEMENTED;
}

/* Convert a list of SIDs */
wbcErr wbcSidsToUnixIds(const struct wbcDomainSid *sids, uint32_t num_sids,
            struct wbcUnixId *ids)
{
    int ret;
    char *sid_str;
    uint32_t id;
    enum sss_id_type type;
    size_t c;
    wbcErr wbc_status;

    for (c = 0; c < num_sids; c++) {
        type = SSS_ID_TYPE_NOT_SPECIFIED;
        wbc_status = wbcSidToString(&sids[c], &sid_str);
        if (WBC_ERROR_IS_OK(wbc_status)) {
            ret = sss_nss_getidbysid(sid_str, &id, &type);
            wbcFreeMemory(sid_str);
            if (ret != 0) {
                type = SSS_ID_TYPE_NOT_SPECIFIED;
            }
        }

        switch (type) {
        case SSS_ID_TYPE_UID:
            ids[c].type = WBC_ID_TYPE_UID;
            ids[c].id.uid = (uid_t) id;
            break;
        case SSS_ID_TYPE_GID:
            ids[c].type = WBC_ID_TYPE_GID;
            ids[c].id.gid = (gid_t) id;
            break;
        case SSS_ID_TYPE_BOTH:
            ids[c].type = WBC_ID_TYPE_BOTH;
            ids[c].id.uid = (uid_t) id;
            break;
        default:
            ids[c].type = WBC_ID_TYPE_NOT_SPECIFIED;
        }
    }

    return WBC_ERR_SUCCESS;
}

wbcErr wbcUnixIdsToSids(const struct wbcUnixId *ids, uint32_t num_ids,
                        struct wbcDomainSid *sids)
{
    size_t c;
    wbcErr wbc_status;

    for (c = 0; c < num_ids; c++) {
        switch (ids[c].type) {
        case WBC_ID_TYPE_UID:
            wbc_status = wbcUidToSid(ids[c].id.uid, &sids[c]);
            break;
        case WBC_ID_TYPE_GID:
            wbc_status = wbcGidToSid(ids[c].id.gid, &sids[c]);
            break;
        default:
            wbc_status = WBC_ERR_INVALID_PARAM;
        }

        if (!WBC_ERROR_IS_OK(wbc_status)) {
            sids[c] = (struct wbcDomainSid){ 0 };
        };
    }

    return WBC_ERR_SUCCESS;
}
