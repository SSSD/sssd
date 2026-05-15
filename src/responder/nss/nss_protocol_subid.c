/*
    Copyright (C) 2021 Red Hat

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

#include "responder/nss/nss_protocol.h"

errno_t
sss_nss_protocol_fill_subid_ranges(struct sss_nss_ctx *nss_ctx,
                                   struct sss_nss_cmd_ctx *cmd_ctx,
                                   struct sss_packet *packet,
                                   struct cache_req_result *result)
{
    static const uint32_t one = 1;
    errno_t ret;
    uint8_t *body;
    size_t body_len;
    size_t rp = 0;
    uint32_t gid, uid, gidCount, uidCount;

    if (!result->count || !result->msgs) {
        return ENOENT;
    }

    uid      = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_SUBID_UID_NUMBER, 0);
    uidCount = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_SUBID_UID_COUND,  0);
    gid      = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_SUBID_GID_NUMBER, 0);
    gidCount = ldb_msg_find_attr_as_uint(result->msgs[0], SYSDB_SUBID_GID_COUNT,  0);
    if (!uid || !gid || !gidCount || !uidCount) {
        return ENOENT;
    }

    /* only single uid & gid range is expected currently */
    ret = sss_packet_grow(packet, (2 + 2*2) * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(&body[rp], &one, &rp);
    SAFEALIGN_COPY_UINT32(&body[rp], &one, &rp);
    SAFEALIGN_COPY_UINT32(&body[rp], &uid, &rp);
    SAFEALIGN_COPY_UINT32(&body[rp], &uidCount, &rp);
    SAFEALIGN_COPY_UINT32(&body[rp], &gid, &rp);
    SAFEALIGN_COPY_UINT32(&body[rp], &gidCount, &rp);

    return EOK;
}
