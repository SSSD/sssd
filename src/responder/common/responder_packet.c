/*
   SSSD

   SSS Client Responder, command parser

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
#include "talloc.h"
#include "util/util.h"
#include "responder/common/responder_packet.h"

#define SSSSRV_PACKET_MEM_SIZE 512

struct sss_packet {
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
 *   SSSSRV_PACKET_MEM_SIZE bytes.
 */
int sss_packet_new(TALLOC_CTX *mem_ctx, size_t size,
                   enum sss_cli_command cmd,
                   struct sss_packet **rpacket)
{
    struct sss_packet *packet;

    packet = talloc(mem_ctx, struct sss_packet);
    if (!packet) return ENOMEM;

    if (size) {
        int n = (size + SSS_NSS_HEADER_SIZE) % SSSSRV_PACKET_MEM_SIZE;
        packet->memsize = (n + 1) * SSSSRV_PACKET_MEM_SIZE;
    } else {
        packet->memsize = SSSSRV_PACKET_MEM_SIZE;
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

/* grows a packet size only in SSSSRV_PACKET_MEM_SIZE chunks */
int sss_packet_grow(struct sss_packet *packet, size_t size)
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
        int n = len % SSSSRV_PACKET_MEM_SIZE + 1;
        totlen += n * SSSSRV_PACKET_MEM_SIZE;
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

        /* re-set pointers if realloc had to move memory */
        if (newmem != packet->buffer) {
            packet->buffer = newmem;
            packet->len = &((uint32_t *)packet->buffer)[0];
            packet->cmd = &((uint32_t *)packet->buffer)[1];
            packet->status = &((uint32_t *)packet->buffer)[2];
            packet->reserved = &((uint32_t *)packet->buffer)[3];
            packet->body = (uint8_t *)&((uint32_t *)packet->buffer)[4];
        }
    }

    *(packet->len) += size;

    return 0;
}

/* reclaim backet previously resrved space in the packet
 * usually done in functione recovering from not fatal erros */
int sss_packet_shrink(struct sss_packet *packet, size_t size)
{
    size_t newlen;

    if (size > *(packet->len)) return EINVAL;

    newlen = *(packet->len) - size;
    if (newlen < SSS_NSS_HEADER_SIZE) return EINVAL;

    *(packet->len) = newlen;
    return 0;
}

int sss_packet_set_size(struct sss_packet *packet, size_t size)
{
    size_t newlen;

    newlen = SSS_NSS_HEADER_SIZE + size;

    /* make sure we do not overflow */
    if (packet->memsize < newlen) return EINVAL;

    *(packet->len) = newlen;

    return 0;
}

int sss_packet_recv(struct sss_packet *packet, int fd)
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

    if (rb == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            return errno;
        }
    }

    if (rb == 0) {
        return ENODATA;
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

int sss_packet_send(struct sss_packet *packet, int fd)
{
    size_t rb;
    size_t len;
    void *buf;

    if (!packet) {
        /* No packet object to write to? */
        return EINVAL;
    }

    buf = packet->buffer + packet->iop;
    len = *packet->len - packet->iop;

    errno = 0;
    rb = send(fd, buf, len, 0);

    if (rb == -1) {
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            return EAGAIN;
        } else {
            return errno;
        }
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

enum sss_cli_command sss_packet_get_cmd(struct sss_packet *packet)
{
    return (enum sss_cli_command)(*packet->cmd);
}

void sss_packet_get_body(struct sss_packet *packet, uint8_t **body, size_t *blen)
{
    *body = packet->body;
    *blen = *packet->len - SSS_NSS_HEADER_SIZE;
}

void sss_packet_set_error(struct sss_packet *packet, int error)
{
    *(packet->status) = error;
}
