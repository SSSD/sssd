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

#ifndef _NSS_PROTOCOL_H_
#define _NSS_PROTOCOL_H_

#include <stdint.h>

#include "util/util.h"
#include "responder/common/responder.h"
#include "responder/common/responder_packet.h"
#include "responder/common/cache_req/cache_req.h"
#include "responder/nss/nss_private.h"
#include "sss_client/idmap/sss_nss_idmap.h"

struct sss_nss_cmd_ctx;

/**
 * Fill SSSD response packet.
 *
 * @return EOK If packet is successfully created and should be sent to client.
 * @return Other errno code on error, an error reply will be sent to client.
 */
typedef errno_t
(*sss_nss_protocol_fill_packet_fn)(struct sss_nss_ctx *nss_ctx,
                                   struct sss_nss_cmd_ctx *cmd_ctx,
                                   struct sss_packet *packet,
                                   struct cache_req_result *result);

struct sss_nss_cmd_ctx {
    enum cache_req_type type;
    struct cli_ctx *cli_ctx;
    struct sss_nss_ctx *nss_ctx;
    struct sss_nss_state_ctx *state_ctx;
    sss_nss_protocol_fill_packet_fn fill_fn;
    uint32_t flags;

    /* For initgroups- */
    const char *rawname;

    /* For enumeration. */
    bool enumeration;
    struct sss_nss_enum_ctx *enum_ctx;
    struct sss_nss_enum_index *enum_index;
    uint32_t enum_limit;

    /* For services. */
    const char *svc_protocol;

    /* For SID lookups. */
    enum sss_id_type sid_id_type;
};

/**
 * If error is EOK, send existing reply packet to the client.
 * If error is ENOENT, create and send empty response.
 * On other error code, create and send an error.
 */
errno_t sss_nss_protocol_done(struct cli_ctx *cli_ctx, errno_t error);

/**
 * Create and send SSSD response packet to the client.
 */
void sss_nss_protocol_reply(struct cli_ctx *cli_ctx,
                        struct sss_nss_ctx *nss_ctx,
                        struct sss_nss_cmd_ctx *cmd_ctx,
                        struct cache_req_result *result,
                        sss_nss_protocol_fill_packet_fn fill_fn);

/* Parse input packet. */

errno_t
sss_nss_protocol_parse_name(struct cli_ctx *cli_ctx, const char **_rawname);

errno_t
sss_nss_protocol_parse_name_ex(struct cli_ctx *cli_ctx, const char **_rawname,
                           uint32_t *_flags);

errno_t
sss_nss_protocol_parse_id(struct cli_ctx *cli_ctx, uint32_t *_id);

errno_t
sss_nss_protocol_parse_id_ex(struct cli_ctx *cli_ctx, uint32_t *_id,
                         uint32_t *_flags);

errno_t
sss_nss_protocol_parse_limit(struct cli_ctx *cli_ctx, uint32_t *_limit);

errno_t
sss_nss_protocol_parse_svc_name(struct cli_ctx *cli_ctx,
                            const char **_name,
                            const char **_protocol);

errno_t
sss_nss_protocol_parse_svc_port(struct cli_ctx *cli_ctx,
                            uint16_t *_port,
                            const char **_protocol);

errno_t
sss_nss_protocol_parse_cert(struct cli_ctx *cli_ctx,
                        const char **_derb64);

errno_t
sss_nss_protocol_parse_sid(struct cli_ctx *cli_ctx,
                       const char **_sid);

errno_t
sss_nss_protocol_parse_addr(struct cli_ctx *cli_ctx,
                        uint32_t *_af,
			uint32_t *_addrlen,
			uint8_t **_addr);

/* Create response packet. */

errno_t
sss_nss_protocol_fill_pwent(struct sss_nss_ctx *nss_ctx,
                        struct sss_nss_cmd_ctx *cmd_ctx,
                        struct sss_packet *packet,
                        struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_grent(struct sss_nss_ctx *nss_ctx,
                        struct sss_nss_cmd_ctx *cmd_ctx,
                        struct sss_packet *packet,
                        struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_initgr(struct sss_nss_ctx *nss_ctx,
                         struct sss_nss_cmd_ctx *cmd_ctx,
                         struct sss_packet *packet,
                         struct cache_req_result *result);

#ifdef BUILD_SUBID
errno_t
sss_nss_protocol_fill_subid_ranges(struct sss_nss_ctx *sss_nss_ctx,
                                   struct sss_nss_cmd_ctx *cmd_ctx,
                                   struct sss_packet *packet,
                                   struct cache_req_result *result);
#endif

errno_t
sss_nss_protocol_fill_netgrent(struct sss_nss_ctx *nss_ctx,
                               struct sss_nss_cmd_ctx *cmd_ctx,
                               struct sss_packet *packet,
                               struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_svcent(struct sss_nss_ctx *nss_ctx,
                             struct sss_nss_cmd_ctx *cmd_ctx,
                             struct sss_packet *packet,
                             struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_sid(struct sss_nss_ctx *nss_ctx,
                      struct sss_nss_cmd_ctx *cmd_ctx,
                      struct sss_packet *packet,
                      struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_orig(struct sss_nss_ctx *nss_ctx,
                       struct sss_nss_cmd_ctx *cmd_ctx,
                       struct sss_packet *packet,
                       struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_name(struct sss_nss_ctx *nss_ctx,
                       struct sss_nss_cmd_ctx *cmd_ctx,
                       struct sss_packet *packet,
                       struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_single_name(struct sss_nss_ctx *nss_ctx,
                              struct sss_nss_cmd_ctx *cmd_ctx,
                              struct sss_packet *packet,
                              struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_name_list_all_domains(struct sss_nss_ctx *nss_ctx,
                                        struct sss_nss_cmd_ctx *cmd_ctx,
                                        struct sss_packet *packet,
                                        struct cache_req_result **results);

errno_t
sss_nss_protocol_fill_id(struct sss_nss_ctx *nss_ctx,
                     struct sss_nss_cmd_ctx *cmd_ctx,
                     struct sss_packet *packet,
                     struct cache_req_result *result);

errno_t
sss_nss_protocol_fill_hostent(struct sss_nss_ctx *nss_ctx,
                          struct sss_nss_cmd_ctx *cmd_ctx,
                          struct sss_packet *packet,
                          struct cache_req_result *result);
errno_t
sss_nss_protocol_fill_netent(struct sss_nss_ctx *nss_ctx,
                         struct sss_nss_cmd_ctx *cmd_ctx,
                         struct sss_packet *packet,
                         struct cache_req_result *result);

#endif /* _NSS_PROTOCOL_H_ */
