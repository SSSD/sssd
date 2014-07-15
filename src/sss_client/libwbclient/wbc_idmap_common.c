/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007

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

#include "libwbclient.h"

/* Convert a Windows SID to a Unix uid if there already is a mapping */
wbcErr wbcQuerySidToUid(const struct wbcDomainSid *sid,
            uid_t *puid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Convert a Unix uid to a Windows SID if there already is a mapping */
wbcErr wbcQueryUidToSid(uid_t uid,
            struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Convert a Windows SID to a Unix gid if there already is a mapping */
wbcErr wbcQuerySidToGid(const struct wbcDomainSid *sid,
            gid_t *pgid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}


/* Convert a Unix gid to a Windows SID if there already is a mapping */
wbcErr wbcQueryGidToSid(gid_t gid,
            struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set an user id mapping - not implemented any more */
wbcErr wbcSetUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set a group id mapping - not implemented any more */
wbcErr wbcSetGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Remove a user id mapping - not implemented any more */
wbcErr wbcRemoveUidMapping(uid_t uid, const struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Remove a group id mapping - not implemented any more */
wbcErr wbcRemoveGidMapping(gid_t gid, const struct wbcDomainSid *sid)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set the highwater mark for allocated uids - not implemented any more */
wbcErr wbcSetUidHwm(uid_t uid_hwm)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}

/* Set the highwater mark for allocated gids - not implemented any more */
wbcErr wbcSetGidHwm(gid_t gid_hwm)
{
    return WBC_ERR_NOT_IMPLEMENTED;
}
