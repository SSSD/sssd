/*
   SSSD

   NSS Responder, header file

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

#ifndef __NSSSRV_H__
#define __NSSSRV_H__

#include <stdint.h>
#include "../nss_client/sss_nss.h"

struct nss_packet;

struct cli_request {
    enum sss_nss_command cmd;
    void *cmd_req;

    /* original request from the wire */
    struct nss_packet *in;

    /* reply data */
    struct nss_packet *out;
};

/* from nsssrv_packet.c */
int nss_packet_new(TALLOC_CTX *mem_ctx, size_t size,
                      struct nss_packet **rpacket);
int nss_packet_grow(struct nss_packet *packet, size_t size);
int nss_packet_recv(struct nss_packet *packet, int fd);
int nss_packet_send(struct nss_packet *packet, int fd);

#endif /* __NSSSRV_H__ */
