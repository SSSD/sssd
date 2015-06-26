/*
   Unix SMB/CIFS implementation.

   Winbind client API

   Copyright (C) Gerald (Jerry) Carter 2007
   Copyright (C) Volker Lendecke 2010


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

#include <stdio.h>

#include "libwbclient.h"

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

/* Convert a sid to a string into a buffer. Return the string
 * length. If buflen is too small, return the string length that would
 * result if it was long enough. */
int wbcSidToStringBuf(const struct wbcDomainSid *sid, char *buf, int buflen)
{
    uint64_t id_auth;
    int i, ofs;

    if (!sid) {
        strncpy(buf, "(NULL SID)", buflen);
        buf[buflen < 10 ? buflen :10] = '\0';
        return 10;    /* strlen("(NULL SID)") */
    }

    id_auth = (uint64_t)sid->id_auth[5] +
        ((uint64_t)sid->id_auth[4] << 8) +
        ((uint64_t)sid->id_auth[3] << 16) +
        ((uint64_t)sid->id_auth[2] << 24) +
        ((uint64_t)sid->id_auth[1] << 32) +
        ((uint64_t)sid->id_auth[0] << 40);

    ofs = snprintf(buf, buflen, "S-%hhu-", (unsigned char)sid->sid_rev_num);
    if (id_auth >= UINT32_MAX) {
        ofs += snprintf(buf + ofs, MAX(buflen - ofs, 0), "0x%llx",
                (unsigned long long)id_auth);
    } else {
        ofs += snprintf(buf + ofs, MAX(buflen - ofs, 0), "%llu",
                (unsigned long long)id_auth);
    }

    for (i = 0; i < sid->num_auths; i++) {
        ofs += snprintf(buf + ofs, MAX(buflen - ofs, 0), "-%u",
                (unsigned int)sid->sub_auths[i]);
    }
    return ofs;
}

/* Convert a binary SID to a character string */
wbcErr wbcSidToString(const struct wbcDomainSid *sid,
              char **sid_string)
{
    char buf[WBC_SID_STRING_BUFLEN];
    char *result;
    int len;

    if (!sid) {
        return WBC_ERR_INVALID_SID;
    }

    len = wbcSidToStringBuf(sid, buf, sizeof(buf));

    if (len+1 > sizeof(buf)) {
        return WBC_ERR_INVALID_SID;
    }

    result = (char *)wbcAllocateMemory(len+1, 1, NULL);
    if (result == NULL) {
        return WBC_ERR_NO_MEMORY;
    }
    memcpy(result, buf, len+1);

    *sid_string = result;
    return WBC_ERR_SUCCESS;
}

#define AUTHORITY_MASK    (~(0xffffffffffffULL))

/* Convert a character string to a binary SID */
wbcErr wbcStringToSid(const char *str,
              struct wbcDomainSid *sid)
{
    const char *p;
    char *q;
    uint64_t x;
    wbcErr wbc_status = WBC_ERR_UNKNOWN_FAILURE;

    if (!sid) {
        wbc_status = WBC_ERR_INVALID_PARAM;
        BAIL_ON_WBC_ERROR(wbc_status);
    }

    /* Sanity check for either "S-" or "s-" */

    if (!str
        || (str[0]!='S' && str[0]!='s')
        || (str[1]!='-'))
    {
        wbc_status = WBC_ERR_INVALID_PARAM;
        BAIL_ON_WBC_ERROR(wbc_status);
    }

    /* Get the SID revision number */

    p = str+2;
    x = (uint64_t)strtoul(p, &q, 10);
    if (x==0 || x > UINT8_MAX || !q || *q!='-') {
        wbc_status = WBC_ERR_INVALID_SID;
        BAIL_ON_WBC_ERROR(wbc_status);
    }
    sid->sid_rev_num = (uint8_t)x;

    /*
     * Next the Identifier Authority.  This is stored big-endian in a
     * 6 byte array. If the authority value is >= UINT_MAX, then it should
     * be expressed as a hex value, according to MS-DTYP.
     */
    p = q+1;
    x = strtoull(p, &q, 0);
    if (!q || *q!='-' || (x & AUTHORITY_MASK)) {
        wbc_status = WBC_ERR_INVALID_SID;
        BAIL_ON_WBC_ERROR(wbc_status);
    }
    sid->id_auth[5] = (x & 0x0000000000ffULL);
    sid->id_auth[4] = (x & 0x00000000ff00ULL) >> 8;
    sid->id_auth[3] = (x & 0x000000ff0000ULL) >> 16;
    sid->id_auth[2] = (x & 0x0000ff000000ULL) >> 24;
    sid->id_auth[1] = (x & 0x00ff00000000ULL) >> 32;
    sid->id_auth[0] = (x & 0xff0000000000ULL) >> 40;

    /* now read the subauthorities */
    p = q +1;
    sid->num_auths = 0;
    while (sid->num_auths < WBC_MAXSUBAUTHS) {
        x = strtoull(p, &q, 10);
        if (p == q)
            break;
        if (x > UINT32_MAX) {
            wbc_status = WBC_ERR_INVALID_SID;
            BAIL_ON_WBC_ERROR(wbc_status);
        }
        sid->sub_auths[sid->num_auths++] = x;

        if (*q != '-') {
            break;
        }
        p = q + 1;
    }

    /* IF we ended early, then the SID could not be converted */

    if (q && *q!='\0') {
        wbc_status = WBC_ERR_INVALID_SID;
        BAIL_ON_WBC_ERROR(wbc_status);
    }

    wbc_status = WBC_ERR_SUCCESS;

done:
    return wbc_status;

}

const char* wbcSidTypeString(enum wbcSidType type)
{
    switch (type) {
    case WBC_SID_NAME_USE_NONE: return "SID_NONE";
    case WBC_SID_NAME_USER:     return "SID_USER";
    case WBC_SID_NAME_DOM_GRP:  return "SID_DOM_GROUP";
    case WBC_SID_NAME_DOMAIN:   return "SID_DOMAIN";
    case WBC_SID_NAME_ALIAS:    return "SID_ALIAS";
    case WBC_SID_NAME_WKN_GRP:  return "SID_WKN_GROUP";
    case WBC_SID_NAME_DELETED:  return "SID_DELETED";
    case WBC_SID_NAME_INVALID:  return "SID_INVALID";
    case WBC_SID_NAME_UNKNOWN:  return "SID_UNKNOWN";
    case WBC_SID_NAME_COMPUTER: return "SID_COMPUTER";
    default:                    return "Unknown type";
    }
}
