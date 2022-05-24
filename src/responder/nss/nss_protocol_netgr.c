/*
    Authors:
        Pavel Březina <pbrezina@redhat.com>

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

#include "db/sysdb.h"
#include "db/sysdb_services.h"
#include "responder/nss/nss_protocol.h"

static errno_t
sss_nss_protocol_fill_netgr_triple(struct sss_packet *packet,
                                   struct sysdb_netgroup_ctx *entry,
                                   size_t *_rp)
{
    struct sized_string host;
    struct sized_string user;
    struct sized_string domain;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    to_sized_string(&host, entry->value.triple.hostname);
    to_sized_string(&user, entry->value.triple.username);
    to_sized_string(&domain, entry->value.triple.domainname);

    if (host.len == 0) {
        host.len = 1;
        host.str = "";
    }

    if (user.len == 0) {
        user.len = 1;
        user.str = "";
    }

    if (domain.len == 0) {
        domain.len = 1;
        domain.str = "";
    }

    ret = sss_packet_grow(packet, sizeof(uint32_t)
                                      + host.len + user.len + domain.len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to grow packet!\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[*_rp], SSS_NETGR_REP_TRIPLE, _rp);
    SAFEALIGN_SET_STRING(&body[*_rp], host.str, host.len, _rp);
    SAFEALIGN_SET_STRING(&body[*_rp], user.str, user.len, _rp);
    SAFEALIGN_SET_STRING(&body[*_rp], domain.str, domain.len, _rp);

    return EOK;
}

static errno_t
sss_nss_protocol_fill_netgr_member(struct sss_packet *packet,
                                   struct sysdb_netgroup_ctx *entry,
                                   size_t *_rp)
{
    struct sized_string group;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    if (entry->value.groupname == NULL || entry->value.groupname[0] == '\0') {
        DEBUG(SSSDBG_CRIT_FAILURE, "Empty netgroup member!\n");
        return EINVAL;
    }

    to_sized_string(&group, entry->value.groupname);

    ret = sss_packet_grow(packet, sizeof(uint32_t) + group.len);
    if (ret != EOK) {
        DEBUG(SSSDBG_CRIT_FAILURE, "Unable to grow packet!\n");
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);

    SAFEALIGN_SET_UINT32(&body[*_rp], SSS_NETGR_REP_GROUP, _rp);
    SAFEALIGN_SET_STRING(&body[*_rp], group.str, group.len, _rp);

    return EOK;
}

errno_t
sss_nss_protocol_fill_netgrent(struct sss_nss_ctx *nss_ctx,
                           struct sss_nss_cmd_ctx *cmd_ctx,
                           struct sss_packet *packet,
                           struct cache_req_result *result)
{
    struct sysdb_netgroup_ctx **entries;
    struct sysdb_netgroup_ctx *entry;
    struct sss_nss_enum_index *idx;
    uint32_t num_results;
    size_t rp;
    size_t body_len;
    uint8_t *body;
    errno_t ret;

    idx = cmd_ctx->enum_index;
    entries = cmd_ctx->enum_ctx->netgroup;

    if (idx->result > cmd_ctx->enum_ctx->netgroup_count) {
        DEBUG(SSSDBG_CRIT_FAILURE,
              "Inconsistent state while processing netgroups.\n");
        ret = EINVAL;
        goto done;
    }

    /* First two fields (length and reserved), filled up later. */
    ret = sss_packet_grow(packet, 2 * sizeof(uint32_t));
    if (ret != EOK) {
        return ret;
    }

    rp = 2 * sizeof(uint32_t);

    if (entries == NULL) {
        num_results = 0;
        ret = EOK;
        goto done;
    }

    num_results = 1; /* group was found */
    for (; entries[idx->result] != NULL; idx->result++) {

        entry = entries[idx->result];

        switch (entry->type) {
        case SYSDB_NETGROUP_TRIPLE_VAL:
            ret = sss_nss_protocol_fill_netgr_triple(packet, entry, &rp);
            break;
        case SYSDB_NETGROUP_GROUP_VAL:
            ret = sss_nss_protocol_fill_netgr_member(packet, entry, &rp);
            break;
        default:
            DEBUG(SSSDBG_CRIT_FAILURE, "Unexpected value type %d!\n", entry->type);
            ret = ERR_INTERNAL;
            break;
        }

        if (ret != EOK) {
            goto done;
        }

        num_results++;
    }

    ret = EOK;

done:
    if (ret != EOK) {
        sss_packet_set_size(packet, 0);
        return ret;
    }

    sss_packet_get_body(packet, &body, &body_len);
    SAFEALIGN_COPY_UINT32(body, &num_results, NULL);
    SAFEALIGN_SETMEM_UINT32(body + sizeof(uint32_t), 0, NULL); /* reserved */

    return EOK;
}
