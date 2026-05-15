/*
   SSSD

   SSS Client Responder, header file

   Copyright (C) Simo Sorce <ssorce@redhat.com>	2008

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

#ifndef __SSSSRV_PACKET_H__
#define __SSSSRV_PACKET_H__

#include "sss_client/sss_cli.h"

#define SSS_PACKET_MAX_RECV_SIZE 1024
#define SSS_CERT_PACKET_MAX_RECV_SIZE ( 10 * SSS_PACKET_MAX_RECV_SIZE )
#define SSS_GSSAPI_PACKET_MAX_RECV_SIZE ( 128 * 1024 )

struct sss_packet;

int sss_packet_new(TALLOC_CTX *mem_ctx, size_t size,
                   enum sss_cli_command cmd,
                   struct sss_packet **rpacket);
int sss_packet_grow(struct sss_packet *packet, size_t size);
int sss_packet_shrink(struct sss_packet *packet, size_t size);
int sss_packet_set_size(struct sss_packet *packet, size_t size);
int sss_packet_recv(struct sss_packet *packet, int fd);
int sss_packet_send(struct sss_packet *packet, int fd);
enum sss_cli_command sss_packet_get_cmd(struct sss_packet *packet);
uint32_t sss_packet_get_status(struct sss_packet *packet);
void sss_packet_get_body(struct sss_packet *packet, uint8_t **body, size_t *blen);
void sss_packet_set_error(struct sss_packet *packet, int error);

/* Grow packet and set its body. */
errno_t sss_packet_set_body(struct sss_packet *packet,
                            uint8_t *body,
                            size_t blen);

#endif /* __SSSSRV_PACKET_H__ */
