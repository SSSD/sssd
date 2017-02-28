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
#include <talloc.h>

#include "util/util.h"
#include "responder/common/responder_packet.h"

#define SSSSRV_PACKET_MEM_SIZE 512

struct sss_packet {
    size_t memsize;

    /* Structure of the buffer:
    * Bytes    Content
    * ---------------------------------
    * 0-15     packet header
    * 0-3      packet length (uint32_t)
    * 4-7      command type (uint32_t)
    * 8-11     status (uint32_t)
    * 12-15    reserved
    * 16+      packet body */
    uint8_t *buffer;

    /* io pointer */
    size_t iop;
};

/* Offsets to data in sss_packet's buffer */
#define SSS_PACKET_LEN_OFFSET 0
#define SSS_PACKET_CMD_OFFSET sizeof(uint32_t)
#define SSS_PACKET_ERR_OFFSET (2*(sizeof(uint32_t)))
#define SSS_PACKET_BODY_OFFSET (4*(sizeof(uint32_t)))

static void sss_packet_set_len(struct sss_packet *packet, uint32_t len);
static void sss_packet_set_cmd(struct sss_packet *packet,
                               enum sss_cli_command cmd);
static uint32_t sss_packet_get_len(struct sss_packet *packet);

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
        int n = (size + SSS_NSS_HEADER_SIZE) / SSSSRV_PACKET_MEM_SIZE;
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

    sss_packet_set_len(packet, size + SSS_NSS_HEADER_SIZE);
    sss_packet_set_cmd(packet, cmd);

    packet->iop = 0;

    *rpacket = packet;

    return EOK;
}

/* grows a packet size only in SSSSRV_PACKET_MEM_SIZE chunks */
int sss_packet_grow(struct sss_packet *packet, size_t size)
{
    size_t totlen, len;
    uint8_t *newmem;
    uint32_t packet_len;

    if (size == 0) {
        return EOK;
    }

    totlen = packet->memsize;
    packet_len = sss_packet_get_len(packet);

    len = packet_len + size;

    /* make sure we do not overflow */
    if (totlen < len) {
        int n = len / SSSSRV_PACKET_MEM_SIZE + 1;
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
        }
    }

    packet_len += size;
    sss_packet_set_len(packet, packet_len);


    return 0;
}

/* reclaim backet previously resrved space in the packet
 * usually done in functione recovering from not fatal erros */
int sss_packet_shrink(struct sss_packet *packet, size_t size)
{
    size_t newlen;
    size_t oldlen = sss_packet_get_len(packet);

    if (size > oldlen) return EINVAL;

    newlen = oldlen - size;
    if (newlen < SSS_NSS_HEADER_SIZE) return EINVAL;

    sss_packet_set_len(packet, newlen);
    return 0;
}

int sss_packet_set_size(struct sss_packet *packet, size_t size)
{
    size_t newlen;

    newlen = SSS_NSS_HEADER_SIZE + size;

    /* make sure we do not overflow */
    if (packet->memsize < newlen) return EINVAL;

    sss_packet_set_len(packet, newlen);

    return 0;
}

int sss_packet_recv(struct sss_packet *packet, int fd)
{
    size_t rb;
    size_t len;
    void *buf;
    size_t new_len;
    int ret;

    buf = (uint8_t *)packet->buffer + packet->iop;
    if (packet->iop > 4) len = sss_packet_get_len(packet) - packet->iop;
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

    if (sss_packet_get_len(packet) > packet->memsize) {
        /* Allow certificate based requests to use larger buffer but not
         * larger than SSS_CERT_PACKET_MAX_RECV_SIZE. Due to the way
         * sss_packet_grow() works the packet len must be set to '0' first and
         * then grow to the expected size. */
        if ((sss_packet_get_cmd(packet) == SSS_NSS_GETNAMEBYCERT
                    || sss_packet_get_cmd(packet) == SSS_NSS_GETLISTBYCERT)
                && packet->memsize < SSS_CERT_PACKET_MAX_RECV_SIZE
                && (new_len = sss_packet_get_len(packet))
                                   < SSS_CERT_PACKET_MAX_RECV_SIZE) {
            new_len = sss_packet_get_len(packet);
            sss_packet_set_len(packet, 0);
            ret = sss_packet_grow(packet, new_len);
            if (ret != EOK) {
                return ret;
            }
        } else {
            return EINVAL;
        }
    }

    packet->iop += rb;
    if (packet->iop < 4) {
        return EAGAIN;
    }

    if (packet->iop < sss_packet_get_len(packet)) {
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
    len = sss_packet_get_len(packet) - packet->iop;

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

    if (packet->iop < sss_packet_get_len(packet)) {
        return EAGAIN;
    }

    return EOK;
}

enum sss_cli_command sss_packet_get_cmd(struct sss_packet *packet)
{
    uint32_t cmd;

    SAFEALIGN_COPY_UINT32(&cmd, packet->buffer + SSS_PACKET_CMD_OFFSET, NULL);
    return (enum sss_cli_command)cmd;
}

uint32_t sss_packet_get_status(struct sss_packet *packet)
{
    uint32_t status;

    SAFEALIGN_COPY_UINT32(&status, packet->buffer + SSS_PACKET_ERR_OFFSET,
                          NULL);
    return status;
}

void sss_packet_get_body(struct sss_packet *packet, uint8_t **body, size_t *blen)
{
    *body = packet->buffer + SSS_PACKET_BODY_OFFSET;
    *blen = sss_packet_get_len(packet) - SSS_NSS_HEADER_SIZE;
}

void sss_packet_set_error(struct sss_packet *packet, int error)
{
    SAFEALIGN_SETMEM_UINT32(packet->buffer + SSS_PACKET_ERR_OFFSET, error,
                            NULL);
}

static void sss_packet_set_len(struct sss_packet *packet, uint32_t len)
{
    SAFEALIGN_SETMEM_UINT32(packet->buffer + SSS_PACKET_LEN_OFFSET, len, NULL);
}

static void sss_packet_set_cmd(struct sss_packet *packet,
                               enum sss_cli_command cmd)
{
    SAFEALIGN_SETMEM_UINT32(packet->buffer + SSS_PACKET_CMD_OFFSET, cmd, NULL);
}

static uint32_t sss_packet_get_len(struct sss_packet *packet)
{
    uint32_t len;

    SAFEALIGN_COPY_UINT32(&len, packet->buffer + SSS_PACKET_LEN_OFFSET, NULL);
    return len;
}
