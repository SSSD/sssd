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
#include <sys/un.h>
#include "talloc.h"
#include "events.h"
#include "ldb.h"
#include "../nss_client/sss_nss.h"

#define NSS_SBUS_SERVICE_VERSION 0x0001
#define NSS_SBUS_SERVICE_NAME "nss"

struct nss_ldb_ctx;
struct getent_ctx;

struct nss_ctx {
    struct event_context *ev;
    struct fd_event *lfde;
    int lfd;
    struct nss_ldb_ctx *lctx;
    struct confdb_ctx *cdb;
    char *sock_name;
    struct service_sbus_ctx *ss_ctx;
    struct btreemap *domain_map;
};

struct cli_ctx {
    struct event_context *ev;
    struct nss_ldb_ctx *lctx;
    int cfd;
    struct fd_event *cfde;
    struct sockaddr_un addr;
    struct cli_request *creq;
    struct getent_ctx *gctx;
};

struct nss_packet;

struct cli_request {

    /* original request from the wire */
    struct nss_packet *in;

    /* reply data */
    struct nss_packet *out;
};

/* from nsssrv_packet.c */
int nss_packet_new(TALLOC_CTX *mem_ctx, size_t size,
                   enum sss_nss_command cmd,
                   struct nss_packet **rpacket);
int nss_packet_grow(struct nss_packet *packet, size_t size);
int nss_packet_recv(struct nss_packet *packet, int fd);
int nss_packet_send(struct nss_packet *packet, int fd);
enum sss_nss_command nss_packet_get_cmd(struct nss_packet *packet);
void nss_packet_get_body(struct nss_packet *packet, uint8_t **body, size_t *blen);
void nss_packet_set_error(struct nss_packet *packet, int error);

/* from nsssrv_cmd.c */
int nss_cmd_execute(struct cli_ctx *cctx);

#endif /* __NSSSRV_H__ */
