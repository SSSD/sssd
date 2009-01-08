/*
   SSSD

   NSS Responder, command parser

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

#include <sys/types.h>
#include <sys/socket.h>
#include <string.h>
#include <errno.h>
#include "../talloc/talloc.h"
#include "util/util.h"
#include "nss/nsssrv.h"

#define NSSSRV_PACKET_MEM_SIZE 512

struct nss_packet {
    size_t memsize;
    uint8_t *buffer;

    /* header */
    uint32_t *len;
    uint32_t *cmd;
    uint32_t *status;
    uint32_t *reserved;

    uint8_t *body;

    /* io pointer */
    size_t iop;
};

/*
 * Allocate a new packet structure
 *
 * - if size is defined use it otherwise the default packet will be
 *   NSSSRV_PACKET_MEM_SIZE bytes.
 */
int nss_packet_new(TALLOC_CTX *mem_ctx, size_t size,
                   enum sss_nss_command cmd,
                   struct nss_packet **rpacket)
{
    struct nss_packet *packet;

    packet = talloc(mem_ctx, struct nss_packet);
    if (!packet) return ENOMEM;

    if (size) {
        int n = (size + SSS_NSS_HEADER_SIZE) % NSSSRV_PACKET_MEM_SIZE;
        packet->memsize = (n + 1) * NSSSRV_PACKET_MEM_SIZE;
    } else {
        packet->memsize = NSSSRV_PACKET_MEM_SIZE;
    }

    packet->buffer = talloc_size(packet, packet->memsize);
    if (!packet->buffer) {
        talloc_free(packet);
        return ENOMEM;
    }
    memset(packet->buffer, 0, SSS_NSS_HEADER_SIZE);

    packet->len = &((uint32_t *)packet->buffer)[0];
    packet->cmd = &((uint32_t *)packet->buffer)[1];
    packet->status = &((uint32_t *)packet->buffer)[2];
    packet->reserved = &((uint32_t *)packet->buffer)[3];
    packet->body = (uint8_t *)&((uint32_t *)packet->buffer)[4];

    *(packet->len) = size + SSS_NSS_HEADER_SIZE;
    *(packet->cmd) = cmd;

    packet->iop = 0;

    *rpacket = packet;

    return EOK;
}

/* grows a packet size only in NSSSRV_PACKET_MEM_SIZE chunks */
int nss_packet_grow(struct nss_packet *packet, size_t size)
{
    size_t totlen, len;
    uint8_t *newmem;

    if (size == 0) {
        return EOK;
    }

    totlen = packet->memsize;
    len = *packet->len + size;

    /* make sure we do not overflow */
    if (totlen < len) {
        int n = len % NSSSRV_PACKET_MEM_SIZE + 1;
        totlen += n * NSSSRV_PACKET_MEM_SIZE;
        if (totlen < len) {
            return EINVAL;
        }
    }

    if (totlen > packet->memsize) {
        newmem = talloc_realloc_size(packet, packet->buffer, totlen);
        if (!newmem) {
            return ENOMEM;
        }

        packet->memsize = totlen;
        packet->buffer = newmem;
        packet->len = &((uint32_t *)packet->buffer)[0];
        packet->cmd = &((uint32_t *)packet->buffer)[1];
        packet->status = &((uint32_t *)packet->buffer)[2];
        packet->reserved = &((uint32_t *)packet->buffer)[3];
        packet->body = (uint8_t *)&((uint32_t *)packet->buffer)[4];
    }

    *(packet->len) += size;

    return 0;
}

int nss_packet_recv(struct nss_packet *packet, int fd)
{
    size_t rb;
    size_t len;
    void *buf;

    buf = packet->buffer + packet->iop;
    if (packet->iop > 4) len = *packet->len - packet->iop;
    else len = packet->memsize - packet->iop;

    /* check for wrapping */
    if (len > packet->memsize) {
        return EINVAL;
    }

    errno = 0;
    rb = recv(fd, buf, len, 0);

    if (rb == -1 && errno == EAGAIN) {
        return EAGAIN;
    }

    if (rb == 0) {
        return EIO;
    }

    if (*packet->len > packet->memsize) {
        return EINVAL;
    }

    packet->iop += rb;
    if (packet->iop < 4) {
        return EAGAIN;
    }

    if (packet->iop < *packet->len) {
        return EAGAIN;
    }

    return EOK;
}

int nss_packet_send(struct nss_packet *packet, int fd)
{
    size_t rb;
    size_t len;
    void *buf;

    buf = packet->buffer + packet->iop;
    len = *packet->len - packet->iop;

    errno = 0;
    rb = send(fd, buf, len, 0);

    if (rb == -1 && errno == EAGAIN) {
        return EAGAIN;
    }

    if (rb == 0) {
        return EIO;
    }

    packet->iop += rb;

    if (packet->iop < *packet->len) {
        return EAGAIN;
    }

    return EOK;
}

enum sss_nss_command nss_packet_get_cmd(struct nss_packet *packet)
{
    return (enum sss_nss_command)(*packet->cmd);
}

void nss_packet_get_body(struct nss_packet *packet, uint8_t **body, size_t *blen)
{
    *body = packet->body;
    *blen = *packet->len - SSS_NSS_HEADER_SIZE;
}

void nss_packet_set_error(struct nss_packet *packet, int error)
{
    *(packet->status) = error;
}
